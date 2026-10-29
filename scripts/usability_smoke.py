"""Task-based user acceptance, offline and using disposable account profiles."""
import json
from pathlib import Path
import tempfile
import threading
import time
from unittest.mock import patch

from playwright.sync_api import sync_playwright, expect
from envscope.accounts import AccountManager
from envscope.check_catalog import check_catalog
from envscope.environment_info import cli_information, device_information
from envscope.model import Finding, Status
from envscope.operations import Operations
from envscope.legacy import LegacyBridge
from envscope.service import make_server
from envscope.state import StateStore
from envscope.maintenance import Maintenance
from scripts.browser_smoke import OfflineScheduler
from scripts.environment_fixtures import fixture

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'artifacts' / 'usability'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summary = {}
    with tempfile.TemporaryDirectory() as temporary, sync_playwright() as runtime:
        home = Path(temporary).resolve()
        events = []
        store = StateStore(memory=True)
        store.save_settings({'usage':'desktop','connection_mode':'direct','usage_country':'JP'}, confirm_environment=True)
        manager = AccountManager(home / '.claude-switcher', home / 'profile',
                                 stop_app=lambda: events.append('stop') or True,
                                 launch_app=lambda: events.append('launch') or True)
        manager.data_dir.mkdir()
        (manager.data_dir / 'fixture.txt').write_text('ACCOUNT_A_FIXTURE', encoding='utf-8')
        def no_legacy(*a, **kw):
            raise AssertionError('Never execute the original backend')
        operations = Operations(store, home, account_manager=manager, discoverer=lambda: [], region_lookup=lambda params: {'state':'unavailable','reason':'离线夹具'},
                                legacy=LegacyBridge(home=home, runner=no_legacy),
                                launcher=lambda: events.append('launch') or True)
        operations.config_remedies.environ = {}
        def audit(*args, **kwargs):
            rows = fixture(home, store.settings())
            data = {f.id: f for f in rows}
            for key in ('proxy', 'tun', 'ipv6', 'guard', 'rules'):
                data['baseline.' + key].status = Status.PASS
            data['baseline.reachability'].status = Status.PASS
            data['baseline.reachability'].evidence = [{'endpoint': 'https://claude.ai/', 'http_status': 200, 'tls_verified': True}]
            data['extra.desktop'].evidence = [{'found': True}]
            data['extra.config'].evidence = [{'exists': False}]
            data['extra.account'].evidence = [manager.inspect_integrity()]
            return rows
        operations.maintenance = Maintenance(store, remedies=operations.config_remedies, scheduler=OfflineScheduler(), auditor=audit, home=home)
        server = make_server(auditor=audit, store=store, operations=operations)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f'http://127.0.0.1:{server.server_port}'
        browser = runtime.chromium.launch()
        try:
            for width in (1024, 1280, 1440):
                context = browser.new_context(viewport={'width': width, 'height': 900}, locale='zh-CN', accept_downloads=True)
                page = context.new_page()
                errors = []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*', lambda route: route.abort())
                page.goto(origin, wait_until='networkidle')
                if page.locator('#learning-panel').is_visible():
                    page.locator('#learning-skip').click()
                expect(page.locator('#connection-status')).to_contain_text('已连接')
                page.get_by_role('button', name='全部检查', exact=True).click()
                expect(page.locator('[data-inspection]')).to_have_count(57)
                expect(page.locator('#all-checks-context')).to_contain_text('尚未检测')
                page.locator('#check-group').select_option('baseline')
                expect(page.locator('[data-inspection]')).to_have_count(14)
                page.locator('#check-group').select_option('extra')
                expect(page.locator('[data-inspection]')).to_have_count(19)
                page.locator('#check-group').select_option('all')
                page.locator('#check-search').fill('证书')
                assert 0 < page.locator('[data-inspection]').count() < 57
                page.locator('#check-search').fill('no-such-fixture')
                expect(page.locator('#all-checks-list')).to_contain_text('没有符合条件')
                page.locator('#check-search').fill('')
                page.locator('#check-search').focus()
                page.keyboard.press('Tab')
                expect(page.locator('#check-group')).to_be_focused()
                page.locator('[data-inspection="extra.config"]>summary').click()
                expect(page.locator('[data-inspection="extra.config"]')).to_contain_text('下一步')
                page.locator('#check-group').select_option('extra')
                page.locator('[data-inspection="extra.dns_resolution"]>summary').click()
                page.evaluate('window.scrollTo(0,0)')
                page.screenshot(path=str(OUT / f'{width}-checks.png'))
                page.locator('#check-group').select_option('all')

                page.get_by_role('button', name='工具', exact=True).click()
                with patch('envscope.operations.cli_information', side_effect=lambda path: cli_information(path, which=lambda n: None)):
                    page.locator('#cli-info').click()
                    expect(page.locator('#environment-output')).to_contain_text('当前进程 PATH 中未找到')
                assert page.locator('#environment-output').evaluate('(n)=>n.getBoundingClientRect().bottom <= innerHeight+1')
                with patch('envscope.operations.device_information', return_value=device_information('Windows', reader=lambda cmd: {'machine': {'Model': '离线测试设备'}, 'gpu': []})):
                    page.locator('#device-info').click()
                    expect(page.locator('#environment-output')).to_contain_text('离线测试设备')
                page.screenshot(path=str(OUT / f'{width}-tools.png'))
                with patch('envscope.operations.device_information', return_value={'state':'partial','title':'设备信息','rows':[{'label':'操作系统','value':'测试系统'}],'note':'显卡未能读取'}):
                    page.locator('#device-info').click()
                    expect(page.locator('#environment-output')).to_contain_text('部分信息尚未取得')
                    expect(page.locator('#environment-output')).not_to_contain_text('离线测试设备')
                page.locator('#browser-info').click()
                expect(page.locator('#environment-output')).to_contain_text('仅在本页展示')
                with page.expect_download() as downloaded:
                    page.locator('#support-bundle').click()
                payload = json.loads(Path(downloaded.value.path()).read_text(encoding='utf-8'))
                assert payload['contains_sensitive'] is False

                page.get_by_role('button', name='账号', exact=True).click()
                expect(page.locator('.account-guide')).to_contain_text('不是邮箱或已注册账号')
                expect(page.locator('#account-force-close')).not_to_be_checked()
                page.locator('#new-slot').fill('错误代号')
                page.locator('#account-add').click()
                expect(page.locator('#account-output')).to_contain_text('显示名称可以使用中文')
                if width == 1024:
                    page.once('dialog', lambda d: d.dismiss())
                    page.locator('[data-account="B"]').get_by_role('button', name='首次登录', exact=True).click()
                    assert events == [] and not manager.state_dir.exists()
                    page.once('dialog', lambda d: d.accept())
                    page.locator('[data-account="B"]').get_by_role('button', name='首次登录', exact=True).click()
                    expect(page.locator('#account-output')).to_contain_text('操作已阻止')
                    assert events == [] and not manager.state_dir.exists()
                page.locator('#account-check').click()
                expect(page.locator('#account-readiness')).to_contain_text('本轮启动条件已核实', timeout=15000)
                if width == 1024:
                    page.once('dialog', lambda d: d.accept())
                    page.locator('[data-account="A"]').get_by_role('button', name='保存当前资料到 A', exact=True).click()
                    expect(page.locator('#account-output')).to_contain_text('已准备槽位 A')
                    normal_stop = manager.stop_app
                    manager.stop_app = lambda: False
                    manager.force_stop_app = lambda: events.append('forced-exit') or True
                    page.locator('#account-force-close').check()
                    def approve_force(dialog):
                        assert '强制退出' in dialog.message and '未保存内容可能丢失' in dialog.message
                        dialog.accept()
                    page.once('dialog', approve_force)
                    page.locator('[data-account="B"]').get_by_role('button', name='首次登录', exact=True).click()
                    expect(page.locator('#account-output')).to_contain_text('已准备槽位 B')
                    expect(page.locator('#account-force-close')).not_to_be_checked()
                    assert 'forced-exit' in events
                    manager.stop_app = normal_stop
                    assert (manager.accounts_dir / 'A/fixture.txt').read_text() == 'ACCOUNT_A_FIXTURE'
                    (manager.data_dir / 'fixture.txt').write_text('ACCOUNT_B_FIXTURE', encoding='utf-8')
                    page.once('dialog', lambda d: d.accept())
                    page.locator('[data-account="A"]').get_by_role('button', name='切换并打开', exact=True).click()
                    expect(page.locator('#account-output')).to_contain_text('已准备槽位 A')
                    assert (manager.data_dir / 'fixture.txt').read_text() == 'ACCOUNT_A_FIXTURE'
                    assert (manager.accounts_dir / 'B/fixture.txt').read_text() == 'ACCOUNT_B_FIXTURE'
                page.screenshot(path=str(OUT / f'{width}-accounts.png'), full_page=True)
                page.get_by_role('button', name='全部检查', exact=True).click()
                page.locator('#check-status').select_option('pass')
                assert page.locator('[data-inspection]').count() > 0
                page.locator('#check-status').select_option('all')
                expect(page.locator('#all-checks-context')).to_contain_text('本次检测')

                page.get_by_role('button', name='历史', exact=True).click()
                page.locator('#history-list').get_by_role('button', name='查看', exact=True).first.click()
                page.get_by_role('button', name='全部检查', exact=True).click()
                expect(page.locator('#all-checks-context')).to_contain_text('历史报告')
                page.get_by_role('button', name='检测', exact=True).click()
                page.route('**/api/audit', lambda route: route.fulfill(status=503, content_type='application/json', body='{"error":"fixture_failure"}'))
                page.locator('#start').click()
                expect(page.locator('#verdict')).to_contain_text('系统检测没有完成')
                page.get_by_role('button', name='全部检查', exact=True).click()
                expect(page.locator('#all-checks-context')).to_contain_text('本轮检测没有完成')
                page.locator('#check-status').select_option('pass')
                expect(page.locator('[data-inspection]')).to_have_count(0)
                page.locator('#check-status').select_option('all')
                expect(page.locator('[data-inspection]')).to_have_count(57)
                page.unroute('**/api/audit')

                page.get_by_role('button', name='工具', exact=True).click()
                page.route('**/api/action', lambda route: route.fulfill(status=500, content_type='application/json', body='{"error":"operation_unavailable_or_deadline"}'))
                page.locator('#device-info').click()
                expect(page.locator('#environment-output')).to_contain_text('本次读取未能完成')
                page.unroute('**/api/action')
                # Stale browser tab: service has disappeared. No native action runs.
                page.route('**/api/session', lambda route: route.abort())
                page.evaluate("window.dispatchEvent(new Event('focus'))")
                expect(page.locator('#connection-banner')).to_be_visible()
                expect(page.locator('#connection-message')).to_contain_text('新打开的页面')
                before = list(events)
                page.locator('#cli-info').click()
                assert events == before
                page.screenshot(path=str(OUT / f'{width}-disconnected.png'))
                page.unroute('**/api/session')
                page.locator('#connection-retry').click()
                expect(page.locator('#connection-banner')).to_be_hidden()
                page.locator('#browser-info').click()
                expect(page.locator('#environment-output')).to_contain_text('浏览器信息')
                for name in ('检测', '全部检查', '账号', '工具', '持续维护', '历史', '设置'):
                    page.get_by_role('button', name=name, exact=True).click()
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), name
                page.get_by_role('button', name='工具', exact=True).click()
                page.locator('#project-comparison>summary').click()
                expect(page.locator('#project-comparison')).to_contain_text('仍需维护核心或手动处理')
                # A visible, idle page renews activity without running diagnostics.
                page.clock.install()
                server.last_activity = time.monotonic() - 901
                with page.expect_response(lambda r: r.url.endswith('/api/session')):
                    page.clock.fast_forward(30001)
                assert server.last_activity > time.monotonic() - 5
                if width == 1280:
                    # Catalog failure must not disable independent native information.
                    page.route('**/api/catalog', lambda route: route.fulfill(status=500, content_type='application/json', body='{"error":"catalog_unavailable"}'))
                    page.reload(wait_until='networkidle')
                    expect(page.locator('#catalog-error')).to_be_visible()
                    page.get_by_role('button', name='工具', exact=True).click()
                    with patch('envscope.operations.cli_information', side_effect=lambda path: cli_information(path, which=lambda n: None)):
                        page.locator('#cli-info').click()
                        expect(page.locator('#environment-output')).to_contain_text('当前进程 PATH 中未找到')
                    page.unroute('**/api/catalog')
                    page.locator('#catalog-retry').click()
                    expect(page.locator('#catalog-error')).to_be_hidden()
                    # A stale URL also explains recovery on the initial page load.
                    page.route('**/api/session', lambda route: route.abort())
                    page.reload(wait_until='networkidle')
                    expect(page.locator('#connection-banner')).to_be_visible()
                    page.unroute('**/api/session')
                    page.locator('#connection-retry').click()
                    expect(page.locator('#connection-status')).to_contain_text('已连接')
                assert not errors, errors
                summary[str(width)] = {'check_catalog':56, 'information_panels':'passed', 'failure_feedback':'passed', 'history_and_retest':'passed', 'disconnect_reconnect':'passed', 'visible_page_keepalive':'passed', 'keyboard_filters':'passed', 'comparison':'passed', 'page_errors':errors, 'overflow':False}
                context.close()
            summary['account_round_trip'] = {'isolated_profile_A_preserved':True,'isolated_profile_B_preserved':True,'callbacks':events,'real_accounts_touched':False}
            (OUT / 'result.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
            print(json.dumps(summary, ensure_ascii=False))
        finally:
            browser.close()
            server.shutdown();server.server_close();thread.join(timeout=3)


if __name__ == '__main__':
    main()
