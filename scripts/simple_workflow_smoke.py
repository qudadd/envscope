"""End-to-end desktop workflow using disposable settings, files and OS adapters."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock

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

                    def writer(key, value):
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
                        assert page.locator('#desktop-nav .tab:visible').count() == 1
                        expect(page.locator('#target-confirm')).to_be_enabled()
                        assert page.locator('#target-country option').count() > 240
                        page.screenshot(path=str(out / f'{system}-{width}-initial.png'), full_page=True)
                        page.locator('#learning-skip').click()
                        page.locator('[name=usage_country]').fill('US')
                        expect(page.locator('#target-region-profile')).to_have_value('us-new-york')
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
                        page.locator('#apply-solution').click()
                        expect(page.locator('#resolution')).to_be_visible(timeout=30000)
                        expect(page.locator('#start')).to_be_enabled()
                        assert {key for key, value in writes} == {'timezone', 'locale'}
                        assert not page.locator('#problems [data-problem="baseline.timezone"]').count()
                        page.locator('#flow-upkeep-guard-timezone').check()
                        page.locator('#flow-upkeep-prepare').click()
                        expect(page.locator('#flow-upkeep-plan')).to_contain_text('保持时区')
                        assert not maintenance.scheduler.definition
                        page.locator('#flow-upkeep-plan button').click()
                        expect(page.locator('#flow-upkeep-status')).to_contain_text('等待', timeout=10000)
                        assert maintenance.scheduler.definition
                        page.locator('#flow-upkeep-stop').click()
                        expect(page.locator('#flow-upkeep-status')).to_contain_text('尚未启用')
                        fault[0] = 'permission'
                        page.locator('#start').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=30000)
                        expect(page.locator('#problems')).to_contain_text('权限')
                        assert page.locator('#problems>details[data-manual=true]>summary:visible').count() > 0
                        page.screenshot(path=str(out / f'{system}-{width}-permission.png'), full_page=True)
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
