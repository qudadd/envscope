"""End-to-end desktop workflow using disposable settings, files and OS adapters."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock, patch

from playwright.sync_api import expect, sync_playwright
from envscope.legacy import LegacyBridge
from envscope.maintenance import Maintenance
from envscope.model import Status
from envscope.operations import Operations
from envscope.region_setup import RegionSetup
from envscope.service import make_server
from envscope.state import StateStore
from envscope.watchdog import Watchdog
from scripts.environment_fixtures import fixture
from scripts.ui_navigation import open_page, open_details
from tests.test_maintenance import FakeScheduler


def main():
    out = Path('artifacts/simple-workflow-ui')
    out.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            for system, width in (('Windows', 1024), ('Windows', 1440), ('Darwin', 1280)):
                with tempfile.TemporaryDirectory() as temporary:
                    home = Path(temporary).resolve()
                    store = StateStore(home / 'state')
                    inventory = {'platform': system, 'locale': 'zh-CN', 'network': {
                        'timezone_id': 'China Standard Time' if system == 'Windows' else 'Asia/Shanghai'}}
                    writes, errors, requests = [], [], []
                    fault = [None]
                    deny_write = [False]

                    def writer(key, value):
                        if deny_write[0]:
                            raise PermissionError('fixture: permission denied')
                        writes.append((key, value))
                        if key == 'timezone':
                            inventory['network']['timezone_id'] = value
                        else:
                            inventory[key] = value

                    def auditor(*args, **kwargs):
                        settings = kwargs.get('baseline_config') or store.settings()
                        rows = fixture(home, settings, system, fault=fault[0])
                        for row in rows:
                            if row.id in ('baseline.timezone', 'baseline.locale'):
                                key = row.id.split('.')[1]
                                actual = inventory['network']['timezone_id'] if key == 'timezone' else inventory['locale']
                                desired = settings[key]
                                row.status = Status.PASS if actual.replace('_', '-') == desired.replace('_', '-') else Status.FAIL
                                row.summary = '符合目标' if row.status == Status.PASS else '当前为 ' + actual + '，目标为 ' + desired
                                row.evidence = [{'actual': actual, 'expected': desired}]
                        return rows

                    guard = Watchdog(home, system, reader=lambda: inventory, writer=writer, clients=lambda: [])
                    maintenance = Maintenance(store, home=home, scheduler=FakeScheduler(), watchdog=guard, auditor=auditor)
                    ops = Operations(store, home, maintenance=maintenance, discoverer=lambda: [],
                                     environment_reader=lambda: inventory,
                                     legacy=LegacyBridge(home=home, runner=Mock(side_effect=AssertionError('No vendor execution'))),
                                     region_lookup=lambda params: {'state': 'observed', 'country': 'US', 'ip': '8.8.8.8',
                                                                  'timezone': 'America/New_York', 'reason': '离线模拟'})
                    ops.regions = RegionSetup(store, lambda: inventory, home, system, writer)
                    ops.config_remedies.environ = {}
                    server = make_server(store=store, operations=ops, auditor=auditor)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    context = browser.new_context(viewport={'width': width, 'height': 950}, locale='zh-CN')
                    page = context.new_page()
                    page.on('pageerror', lambda e: errors.append(str(e)))
                    page.add_init_script('window.RTCPeerConnection=undefined')
                    page.route('https://**/*', lambda route: route.abort())
                    page.on('request', lambda request: requests.append(request.post_data_json) if request.url.endswith('/api/action') else None)
                    try:
                        page.goto('http://127.0.0.1:' + str(server.server_port), wait_until='networkidle')
                        expect(page.locator('#audit-content')).to_be_visible()
                        expect(page.locator('#learning-panel')).to_be_visible()
                        expect(page.locator('#audit-results')).to_be_hidden()
                        assert page.locator('#desktop-nav .tab:visible').count() == 3
                        expect(page.locator('#target-confirm')).to_be_enabled()
                        assert page.locator('#target-country option').count() > 240
                        page.screenshot(path=str(out / f'{system}-{width}-initial.png'), full_page=True)
                        page.locator('#learning-skip').click()
                        page.locator('[name=usage_country]').fill('US')
                        try:
                            expect(page.locator('#target-region-profile')).to_have_value('us-new-york')
                        except AssertionError:
                            print({'location':page.locator('#target-ip-status').inner_text(), 'requests':requests[-5:]},flush=True)
                            raise
                        open_details(page, '#target-connection-options')
                        page.locator('#target-form [name=usage]').select_option('cli')
                        page.locator('#target-form [name=connection_mode]').select_option('direct')
                        page.locator('#target-connection-options>summary').click()
                        page.locator('#target-confirm').click()
                        expect(page.locator('#apply-solution')).to_be_visible(timeout=30000)
                        expect(page.locator('#solution-plan')).to_contain_text('时区')
                        assert not writes, 'preview must not write'
                        assert page.locator('#problems>details').count() >= 2
                        assert page.locator('#problems>details>summary:visible').count() == page.locator('#problems>details').count()
                        expect(page.locator('#flow-upkeep')).to_be_visible()
                        expect(page.locator('#more-results')).not_to_have_attribute('open', '')
                        page.screenshot(path=str(out / f'{system}-{width}-problems.png'), full_page=True)
                        # A problem's recheck must replace the consumed preview with a
                        # fresh plan, including region fixes outside legacy repair_count.
                        first_plan = next(r for r in reversed(requests) if r['action'] == 'inspection-plan')
                        timezone_issue = page.locator('#problems>details').filter(has_text='系统时区与您设置的目标不同')
                        timezone_issue.locator('summary').click()
                        timezone_issue.get_by_role('button', name='重新检测', exact=True).click()
                        expect(page.locator('#apply-solution')).to_be_visible(timeout=30000)
                        expect(page.locator('#prepare-solution')).to_be_visible()
                        next_plan = next(r for r in reversed(requests) if r['action'] == 'inspection-plan')
                        assert next_plan['params']['report_id'] != first_plan['params']['report_id']
                        assert not writes, 'rechecking must never apply a plan'
                        # Expired approval cannot write, and must leave a working way
                        # to generate another reviewed plan.
                        for plan in ops.inspection_plans.values():
                            plan['deadline'] = 0
                        page.locator('#apply-solution').click()
                        expect(page.locator('#solution-result')).to_contain_text('方案已失效')
                        expect(page.locator('#prepare-solution')).to_be_enabled()
                        assert not writes
                        # Inject a transport error only at the read-only plan boundary.
                        def fail_preview(route):
                            if route.request.post_data_json.get('action') == 'inspection-plan':
                                route.fulfill(status=503, json={'error': '模拟：方案服务暂时不可用'})
                            else:
                                route.continue_()
                        page.route('**/api/action', fail_preview)
                        page.locator('#prepare-solution').click()
                        expect(page.locator('#solution-output')).to_contain_text('暂时不可用')
                        expect(page.locator('#apply-solution')).to_have_count(0)
                        expect(page.locator('#prepare-solution')).to_be_enabled()
                        page.unroute('**/api/action', fail_preview)
                        page.locator('#prepare-solution').click()
                        expect(page.locator('#apply-solution')).to_be_enabled()
                        assert not writes
                        def waiting_install(route):
                            if route.request.post_data_json.get('action') == 'inspection-apply':
                                route.fulfill(json={'state': 'waiting_install', 'reason': '模拟安装：完成后继续复检'})
                            else:
                                route.continue_()
                        page.route('**/api/action', waiting_install)
                        page.locator('#apply-solution').click()
                        expect(page.get_by_role('button', name='安装完成，继续复检', exact=True)).to_be_enabled()
                        assert not writes
                        page.unroute('**/api/action', waiting_install)
                        page.get_by_role('button', name='安装完成，继续复检', exact=True).click()
                        expect(page.locator('#apply-solution')).to_be_enabled(timeout=30000)
                        expect(page.locator('#solution-result')).to_contain_text('安装后复检已完成')
                        # The real transaction creates its recovery metadata, then the
                        # file replacement fails. Its specific reason must remain visible.
                        with patch('envscope.remedies._replace', side_effect=PermissionError('fixture denied')):
                            page.locator('#apply-solution').click()
                            expect(page.locator('#solution-result')).to_contain_text('已保留原文件备份', timeout=30000)
                            expect(page.locator('#apply-solution')).to_be_enabled(timeout=30000)
                        assert {key for key, value in writes} == {'timezone', 'locale'}
                        page.locator('#apply-solution').click()
                        expect(page.locator('#resolution')).to_be_visible(timeout=30000)
                        expect(page.locator('#start')).to_be_enabled()
                        assert {key for key, value in writes} == {'timezone', 'locale'}
                        expect(page.locator('#solution-result')).to_contain_text('修改已执行')
                        expect(page.locator('#problems [data-problem="target.timezone"]')).to_have_count(0)
                        expect(page.locator('#apply-solution')).to_have_count(0)
                        expect(page.locator('#prepare-solution')).to_be_visible()
                        # Failed recheck keeps the last execution receipt and explains
                        # why a fresh repair is unavailable; recovery uses a new audit.
                        page.route('**/api/audit', lambda route: route.fulfill(status=503, json={'error': 'fixture unavailable'}))
                        page.locator('#start').click()
                        expect(page.locator('#solution-output')).to_contain_text('本轮检测未完成', timeout=30000)
                        expect(page.locator('#prepare-solution')).to_be_visible()
                        expect(page.locator('#prepare-solution')).to_be_disabled()
                        expect(page.locator('#solution-result')).to_contain_text('修改已执行')
                        page.unroute('**/api/audit')
                        page.locator('#start').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=30000)
                        page.locator('#flow-upkeep-guard-timezone').check()
                        page.locator('#flow-upkeep-guard-locale').check()
                        page.locator('#flow-upkeep-prepare').click()
                        expect(page.locator('#flow-upkeep-plan')).to_contain_text('保持时区')
                        assert not maintenance.scheduler.definition
                        page.locator('#flow-upkeep-plan button').click()
                        expect(page.locator('#flow-upkeep-status')).to_contain_text('等待', timeout=10000)
                        assert maintenance.scheduler.definition
                        inventory['network']['timezone_id'] = 'UTC'
                        inventory['locale'] = 'fr-FR'
                        assert maintenance.run_once()['state'] == 'completed'
                        assert inventory['network']['timezone_id'] == ('Eastern Standard Time' if system == 'Windows' else 'America/New_York')
                        assert inventory['locale'] == ('en-US' if system == 'Windows' else 'en_US')
                        status = maintenance.status()
                        assert status['watchdog']['timezone']['state'] == 'restored'
                        assert status['watchdog']['locale']['state'] == 'restored'
                        assert any(e['kind'] == 'watchdog_restored' for e in status['events'])
                        expect(page.locator('#flow-upkeep-status')).to_contain_text('时区', timeout=25000)
                        expect(page.locator('#flow-upkeep-status')).to_contain_text('地区格式')
                        page.screenshot(path=str(out / f'{system}-{width}-guard-restored.png'), full_page=True)
                        page.locator('#flow-upkeep-stop').click()
                        expect(page.locator('#flow-upkeep-status')).to_contain_text('尚未启用')
                        fault[0] = 'permission'
                        page.locator('#start').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=30000)
                        expect(page.locator('#problems')).to_contain_text('权限')
                        assert page.locator('#problems>details[data-manual=true]>summary:visible').count() > 0
                        page.screenshot(path=str(out / f'{system}-{width}-permission.png'), full_page=True)
                        # A denied OS write must survive the automatic recheck with
                        # manual recovery guidance and no fabricated repair success.
                        fault[0] = None
                        inventory['network']['timezone_id'] = 'UTC'
                        deny_write[0] = True
                        previous_writes = list(writes)
                        page.locator('#start').click()
                        expect(page.locator('#apply-solution')).to_be_enabled(timeout=30000)
                        page.locator('#apply-solution').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=30000)
                        expect(page.locator('#solution-result')).to_contain_text('修复尚未完成')
                        expect(page.locator('#solution-result')).to_have_class('solution-output inspection-error')
                        expect(page.locator('#solution-plan')).to_contain_text('上次地区修改尚未完成')
                        expect(page.locator('#prepare-solution')).to_be_visible()
                        expect(page.locator('#apply-solution')).to_have_count(0)
                        assert writes == previous_writes
                        expect(page.get_by_role('button', name='查看地区修改与恢复记录', exact=True)).to_have_count(1)
                        assert inventory['network']['timezone_id'] == 'UTC'
                        page.screenshot(path=str(out / f'{system}-{width}-repair-denied.png'), full_page=True)
                        for name in ('accounts', 'tools', 'checks', 'upkeep', 'settings', 'coverage', 'history', 'audit'):
                            open_page(page, name)
                            expect(page.locator('#page-' + name)).to_be_visible()
                            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                        assert any(r['action'] == 'inspection-plan' for r in requests)
                        assert all(r['confirmed'] is False for r in requests if r['action'].endswith('-plan'))
                        assert not errors, errors
                        results.append({'platform': system, 'width': width, 'single_workflow': True,
                                        'all_issue_summaries_visible': True, 'preview_before_write': True,
                                        'repair_retest': True, 'watchdog_preview_enable_disable': True,
                                        'problem_recheck_fresh_plan': True, 'expired_plan_no_write': True,
                                        'preview_error_retry': True, 'failed_recheck_recovery': True,
                                        'denied_write_manual_recovery': True, 'watchdog_drift_restored_and_logged': True,
                                        'install_continue_previews_remaining': True, 'file_write_failure_reason_retained': True,
                                        'advanced_navigation': True, 'production_changes': False})
                    finally:
                        context.close()
                        server.shutdown()
                        server.server_close()
                        thread.join(3)
        finally:
            browser.close()
    (out / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(results, ensure_ascii=False))


if __name__ == '__main__':
    main()
