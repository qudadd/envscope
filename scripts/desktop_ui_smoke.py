"""Offline UI acceptance for native settings, update consent and permission help."""
import json
from pathlib import Path
import tempfile
import threading
import time
from unittest.mock import Mock

from playwright.sync_api import sync_playwright, expect
from envscope.check_catalog import check_catalog
from envscope.model import Finding, Status
from envscope.operations import Operations
from envscope.permissions import permission_help
from envscope.service import make_server
from envscope.state import StateStore
from envscope.legacy import LegacyBridge


class DesktopFixture:
    def __init__(self):
        self.preferences = {'keep_running': True, 'check_updates': True, 'preview_updates': True}
        self.update = {'state': 'not_checked', 'current': 'v0.8.0-alpha.1'}
        self.calls = []
        self.rollback = False

    def status(self):
        return {'mode': 'native', 'tray': True, 'preferences': self.preferences, 'can_install': True, 'can_rollback': self.rollback, 'updates': self.update}

    def run(self, action, params, confirmed):
        self.calls.append((action, params, confirmed))
        if action == 'desktop-save':
            self.preferences.update(params)
        elif action == 'app-update-check':
            time.sleep(0.2)
            self.update = {'state': 'available', 'current': 'v0.8.0-alpha.1', 'version': 'v0.9.0-alpha.1', 'notes': 'OFFLINE FIXTURE ONLY <script>never execute</script>', 'upstream': {'changed': True, 'note': '先进行兼容性测试，再随软件发布。'}}
        elif action in ('app-update-install', 'app-update-restart', 'app-update-rollback'):
            if confirmed is not True:
                return {'state': 'confirmation_required', 'reason': '离线测试确认：不会实际安装或启动程序。'}
            self.update['state'] = 'ready'
            self.rollback = True
            return {'state': 'ready', 'reason': '离线夹具：已完成。'}
        return {'state': 'completed', 'desktop': self.status()}


def main():
    out = Path('artifacts/desktop-ui')
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    with tempfile.TemporaryDirectory() as directory, sync_playwright() as runtime:
        store = StateStore(Path(directory) / 'state')
        store.save_settings({'usage':'desktop','connection_mode':'direct'}, confirm_environment=True)
        opener = Mock()
        class FixtureOperations(Operations):
            def run(self, action, params, **kwargs):
                if action == 'permission-help':
                    return permission_help(kwargs.get('report'), params, self.home, self.accounts.data_dir, kwargs.get('confirmed'), runner=opener, system='Windows')
                return super().run(action, params, **kwargs)
        operations = FixtureOperations(store, directory, discoverer=lambda: [], legacy=LegacyBridge(home=directory, runner=Mock(side_effect=AssertionError('No vendor execution'))))
        operations.desktop_runtime = DesktopFixture()
        def audit(*args, **kwargs):
            findings = [Finding(c['id'], c['title'], Status.PASS, '离线测试观测', 'test-fixture') for c in check_catalog()]
            by_id = {f.id: f for f in findings}
            by_id['extra.hosts'].status = Status.UNKNOWN
            by_id['extra.hosts'].evidence = [{'error': 'permission_denied'}]
            by_id['extra.cli_paths'].status = Status.SKIPPED
            by_id['extra.cli_env'].status = Status.SKIPPED
            return findings + [Finding('dns.leak', '权威 DNS 出口', Status.UNKNOWN, '本版未实现', 'test-fixture'),
                               Finding('udp.stun', 'UDP 出口', Status.UNKNOWN, '探测超时', 'test-fixture'),
                               Finding('http.egress', 'HTTP 出口', Status.PASS, '离线观测', 'test-fixture')]
        server = make_server(store=store, operations=operations, auditor=audit)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        browser = runtime.chromium.launch()
        try:
            for width in (1024, 1280, 1440):
                operations.desktop_runtime = DesktopFixture()
                opener.reset_mock()
                context = browser.new_context(viewport={'width': width, 'height': 900}, locale='zh-CN')
                page = context.new_page()
                errors = []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*', lambda route: route.abort())
                page.goto('http://127.0.0.1:' + str(server.server_port), wait_until='networkidle')
                if page.locator('#learning-panel').is_visible():
                    page.locator('#learning-skip').click()
                page.locator('[data-page="settings"]').click()
                expect(page.locator('#desktop-mode')).to_contain_text('独立软件正在运行')
                ids = page.locator('[id]').evaluate_all('(nodes)=>nodes.map(n=>n.id)')
                assert len(ids) == len(set(ids))
                page.locator('#desktop-keep').uncheck()
                page.locator('#desktop-save').click()
                expect(page.locator('#software-output')).to_contain_text('已完成')
                assert not operations.desktop_runtime.preferences['keep_running']
                page.locator('#app-update-check').click()
                expect(page.locator('#app-update-check')).to_be_disabled()
                expect(page.locator('#app-update-state')).to_contain_text('发现可用新版')
                page.once('dialog', lambda d: d.dismiss())
                page.locator('#app-update-install').click()
                expect(page.locator('#software-output')).to_contain_text('已取消')
                assert not any(a == 'app-update-install' and c for a, _, c in operations.desktop_runtime.calls)
                page.once('dialog', lambda d: d.accept())
                page.locator('#app-update-install').click()
                expect(page.locator('#app-update-restart')).to_be_visible()
                page.once('dialog', lambda d: d.accept())
                page.locator('#app-update-rollback').click()
                expect(page.locator('#software-output')).to_contain_text('已完成')
                page.screenshot(path=str(out / f'{width}-settings.png'), full_page=True)
                page.locator('[data-page="audit"]').click()
                page.locator('#start').click()
                expect(page.locator('#qualification')).to_be_visible()
                expect(page.locator('#qualification-counts')).to_contain_text('需要读取权限 1 项')
                page.locator('[data-page="checks"]').click()
                page.locator('#check-status').select_option('unknown')
                expect(page.locator('[data-inspection="dns.leak"]')).to_have_count(0)
                expect(page.locator('[data-inspection="extra.cli_paths"]')).to_have_count(0)
                host = page.locator('[data-inspection="extra.hosts"]')
                expect(host).to_contain_text('需要读取权限')
                host.locator('summary').first.click()
                page.once('dialog', lambda d: d.dismiss())
                host.get_by_role('button', name='处理读取权限').click()
                expect(host).to_contain_text('已取消')
                opener.assert_not_called()
                page.once('dialog', lambda d: d.accept())
                host.get_by_role('button', name='处理读取权限').click()
                expect(host).to_contain_text('属性 → 安全')
                assert opener.call_count == 1
                page.screenshot(path=str(out / f'{width}-permissions.png'), full_page=True)
                page.locator('#check-status').select_option('excluded')
                expect(page.locator('[data-inspection="dns.leak"]')).to_contain_text('本版未支持')
                expect(page.locator('[data-inspection="extra.cli_paths"]')).to_contain_text('不适用')
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                assert not errors, errors
                summary[str(width)] = {'software_preferences': True, 'update_cancel_install_rollback': True, 'permission_cancel_open': True, 'unknown_taxonomy': True, 'duplicate_ids': False, 'page_errors': errors, 'overflow': False, 'real_update_or_permission_change': False}
                context.close()
        finally:
            browser.close()
            server.shutdown()
            server.server_close()
            thread.join(3)
    (out / 'result.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
