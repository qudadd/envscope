"""Offline permission-return workflows. No real permissions or OS settings change."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock

from playwright.sync_api import expect, sync_playwright
from envscope.guide import LESSON_VERSION
from envscope.legacy import LegacyBridge
from envscope.operations import Operations
from envscope.permissions import permission_help
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture, target
from scripts.ui_navigation import open_page


def main():
    results = []
    output = Path('artifacts/permission-flow'); output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            for system in ('Windows', 'Darwin'):
                with tempfile.TemporaryDirectory() as directory:
                    home = Path(directory); store = StateStore(home / 'state'); store.complete_learning(LESSON_VERSION)
                    settings = target(system, 'cli', 'direct', usage_country='US')
                    store.save_settings({k: v for k, v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
                    opener = Mock(); calls = []; access = [False]
                    class FixtureOperations(Operations):
                        def run(self, action, params, **kwargs):
                            if action == 'permission-help':
                                return permission_help(kwargs.get('report'), params, home, home / 'Claude', kwargs.get('confirmed'), opener, system)
                            return super().run(action, params, **kwargs)
                    def auditor(*args, **kwargs):
                        calls.append(kwargs.get('selected_checks'))
                        return fixture(home, kwargs['baseline_config'], system, None if access[0] else 'permission')
                    ops = FixtureOperations(store, home, discoverer=lambda: [],
                        legacy=LegacyBridge(platform_name=system, home=home, runner=Mock(side_effect=AssertionError('No vendor execution'))))
                    server = make_server(store=store, operations=ops, auditor=auditor)
                    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                    context = browser.new_context(viewport={'width': 1280, 'height': 900}, locale='zh-CN')
                    page = context.new_page(); errors = []
                    page.on('pageerror', lambda error: errors.append(str(error)))
                    page.add_init_script('window.RTCPeerConnection=undefined;')
                    page.route('https://**/*', lambda route: route.abort())
                    def row(): return page.locator('[data-inspection="target.config"]')
                    def begin():
                        if not row().evaluate('(node)=>node.open'): row().locator('summary').first.click()
                        page.once('dialog', lambda dialog: dialog.accept())
                        row().get_by_role('button', name='处理读取权限').click()
                        expect(page.locator('#permission-status')).to_have_attribute('data-state', 'waiting')
                        expect(page.locator('html')).not_to_have_attribute('data-operation-busy', 'true')
                    try:
                        page.goto('http://127.0.0.1:' + str(server.server_port), wait_until='networkidle')
                        open_page(page, 'checks'); page.locator('#checks-clear').click()
                        row().locator('input[type=checkbox]').check()
                        page.locator('#checks-run').click()
                        expect(row()).to_contain_text('需要读取权限', timeout=30000)
                        initial = list(calls[-1]); count = len(calls)
                        begin()
                        page.evaluate("window.dispatchEvent(new Event('blur'));window.dispatchEvent(new Event('focus'));window.dispatchEvent(new Event('focus'))")
                        expect(page.locator('#permission-status')).to_have_attribute('data-state', 'denied', timeout=30000)
                        assert len(calls) == count + 1 and calls[-1] == initial
                        begin(); page.locator('#permission-cancel').click()
                        page.evaluate("window.dispatchEvent(new Event('blur'));window.dispatchEvent(new Event('focus'))")
                        expect(page.locator('#permission-status')).to_have_attribute('data-state', 'cancelled')
                        assert len(calls) == count + 1
                        begin(); page.locator('#checks-clear').click()
                        expect(page.locator('#permission-status')).to_have_attribute('data-state', 'stale')
                        row().locator('input[type=checkbox]').check()
                        begin(); access[0] = True
                        page.locator('#permission-resume').click()
                        expect(page.locator('#permission-status')).to_have_attribute('data-state', 'verified', timeout=30000)
                        assert calls[-1] == initial and len(calls) == count + 2
                        assert not errors, errors
                        page.screenshot(path=str(output / (system + '.png')), full_page=True)
                        results.append({'system': system, 'same_selection': True, 'single_auto_recheck': True,
                            'denial_preserved': True, 'cancel': True, 'selection_invalidation': True,
                            'fresh_readback': True, 'real_os_consent': False, 'page_errors': errors})
                    finally:
                        context.close(); server.shutdown(); server.server_close(); thread.join(3)
        finally:
            browser.close()
    (output / 'result.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__':
    main()
