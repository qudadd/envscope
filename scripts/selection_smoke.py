"""UI acceptance for selective checks and reviewed changes; all effects are fixtures."""
import json
from pathlib import Path
import tempfile
import threading
import time
from unittest.mock import Mock

from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect, sync_playwright
from envscope.legacy import LegacyBridge
from envscope.model import Status
from envscope.operations import Operations
from envscope.region_setup import RegionSetup
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture, target


def main():
    out = Path('artifacts/selection-ui')
    out.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            for system in ('Windows', 'Darwin'):
                for width in (1024, 1440):
                    with tempfile.TemporaryDirectory() as temp:
                        home = Path(temp).resolve()
                        store = StateStore(home/'state')
                        inventory = {'platform': system, 'locale': 'zh-CN', 'network': {'timezone_id': 'China Standard Time' if system == 'Windows' else 'Asia/Shanghai'}}
                        writes, calls, outbound = [], [], []
                        def writer(key, value):
                            writes.append([key, value])
                            if key == 'timezone':
                                inventory['network']['timezone_id'] = value
                            else:
                                inventory[key] = value
                        class Controller:
                            identity = 'fixture-controller'
                            now = '日本 Tokyo'
                            def groups(self):
                                return [{'name': 'Claude', 'now': self.now, 'nodes': ['美国 New York', '日本 Tokyo']}]
                            def select(self, group, node, expected, restore=False):
                                assert group == 'Claude' and self.now == expected
                                self.now = node
                                writes.append(['node', node])
                        controller = Controller()
                        legacy = LegacyBridge(home=home, runner=Mock(side_effect=AssertionError('No vendor execution')))
                        ops = Operations(store, home, legacy=legacy, discoverer=lambda: [], environment_reader=lambda: inventory,
                                         region_lookup=lambda params: {'state': 'unavailable', 'reason': '离线夹具'})
                        ops.regions = RegionSetup(store, lambda: inventory, home, system, writer, lambda: controller)
                        ops.config_remedies.environ = {}
                        original_run=ops._run
                        def delayed_confirmation(action,*args,**kwargs):
                            if action=='environment-confirm':time.sleep(.2)
                            return original_run(action,*args,**kwargs)
                        ops._run=delayed_confirmation
                        def auditor(*args, **kwargs):
                            calls.append(kwargs.get('selected_checks'))
                            values = fixture(home, kwargs['baseline_config'], system)
                            for f in values:
                                if f.id in ('baseline.timezone', 'baseline.locale', 'baseline.country'):
                                    key = f.id.split('.')[1]
                                    actual = inventory['network']['timezone_id'] if key == 'timezone' else inventory['locale'] if key == 'locale' else 'US' if controller.now.startswith('美国') else 'JP'
                                    desired = kwargs['baseline_config'][key]
                                    f.evidence = [{'actual': actual, 'expected': desired}]
                                    f.status = Status.PASS if actual.replace('_', '-') == desired.replace('_', '-') else Status.FAIL
                                    f.summary = '符合目标' if f.status == Status.PASS else '当前值与目标不同'
                            return values
                        server = make_server(store=store, operations=ops, auditor=auditor)
                        thread = threading.Thread(target=server.serve_forever, daemon=True)
                        thread.start()
                        context = browser.new_context(viewport={'width': width, 'height': 950}, locale='zh-CN')
                        page = context.new_page()
                        errors = []
                        page.on('pageerror', lambda e: errors.append(str(e)))
                        page.add_init_script('window.RTCPeerConnection=undefined;')
                        def block(route):
                            outbound.append(route.request.url)
                            route.abort()
                        page.route('https://**/*', block)
                        try:
                            page.goto('http://127.0.0.1:'+str(server.server_port), wait_until='networkidle')
                            page.locator('#learning-skip').click()
                            expect(page.locator('#target-confirm')).to_be_enabled()
                            open_details(page, '#target-connection-options'); page.locator('#target-form [name=usage]').select_option('cli')
                            open_details(page, '#target-connection-options'); page.locator('#target-form [name=connection_mode]').select_option('tun')
                            page.locator('#target-form [name=usage_country]').fill('US')
                            page.locator('#target-region-profile').select_option('us-new-york')
                            desired = 'Eastern Standard Time' if system == 'Windows' else 'America/New_York'
                            expect(page.locator('#target-form [name=timezone]')).to_have_value(desired)
                            page.screenshot(path=str(out/f'{system}-{width}-target.png'), full_page=True)
                            page.locator('#target-confirm').click()
                            expect(page.locator('#start')).to_be_disabled()
                            expect(page.locator('#start')).to_be_enabled(timeout=30000)
                            expect(page.locator('html')).not_to_have_attribute('data-operation-busy', 'true')
                            open_page(page, 'checks')
                            page.locator('#check-search').fill('时区')
                            page.locator('#checks-clear').click()
                            page.locator('#checks-select-all').click()
                            expect(page.locator('#checks-selected-count')).to_contain_text('57 项')
                            page.locator('#check-search').fill('')
                            assert page.locator('#all-checks-list input:checked').count() == 57
                            page.locator('#checks-clear').click()
                            row = page.locator('[data-inspection="baseline.timezone"]')
                            row.locator('input[type=checkbox]').check()
                            before = len(outbound)
                            page.locator('#checks-run').click()
                            expect(page.locator('#all-checks-context')).to_contain_text('部分检查')
                            expect(page.locator('#checks-run')).to_be_enabled()
                            assert calls[-1] == ['baseline.timezone'] and len(outbound) == before
                            expect(page.locator('[data-inspection="extra.cli_env"]')).to_contain_text('未勾选')
                            page.locator('#checks-repair').click()
                            expect(page.locator('#checks-apply')).to_be_visible()
                            # A late status refresh must not erase a reviewed
                            # plan when neither the catalog nor defaults changed.
                            page.evaluate('''async()=>{
                              const session=await(await fetch('/api/session')).json();
                              const catalog=await(await fetch('/api/catalog',{headers:{'X-EnvScope-Token':session.token}})).json();
                              document.dispatchEvent(new CustomEvent('envscope-catalog',{detail:catalog}));
                            }''')
                            expect(page.locator('#checks-apply')).to_be_visible()
                            expect(page.locator('#checks-plan')).to_contain_text(desired)
                            assert not writes
                            page.locator('#page-checks h1').scroll_into_view_if_needed()
                            page.screenshot(path=str(out/f'{system}-{width}-plan.png'))
                            page.locator('#checks-apply').click()
                            expect(row.locator('.inspection-state')).to_contain_text('通过', timeout=30000)
                            expect(page.locator('html')).not_to_have_attribute('data-operation-busy', 'true')
                            assert writes == [['timezone', desired]]
                            open_page(page, 'audit')
                            open_page(page, 'checks'); page.locator('#target-configure').click()
                            expect(page.locator('#checks-node-note')).to_contain_text('名称不证明')
                            expect(page.locator('#checks-region-undo')).to_be_visible()
                            expect(page.locator('html')).not_to_have_attribute('data-operation-busy', 'true')
                            page.locator('#checks-node').select_option('美国 New York')
                            page.locator('#checks-run').click()
                            expect(page.locator('#checks-run')).to_be_enabled()
                            page.locator('#checks-repair').click()
                            expect(page.locator('#checks-plan')).to_contain_text('日本 Tokyo → 美国 New York')
                            page.locator('#checks-apply').click()
                            expect(page.locator('[data-inspection="baseline.country"] .inspection-state')).to_contain_text('通过', timeout=30000)
                            expect(page.locator('html')).not_to_have_attribute('data-operation-busy', 'true')
                            assert controller.now.startswith('美国')
                            page.locator('#checks-clear').click()
                            page.locator('[data-inspection="dns.leak"] input').check()
                            page.locator('#checks-run').click()
                            expect(page.locator('#checks-run')).to_be_enabled()
                            dns = page.locator('[data-inspection="dns.leak"]')
                            expect(dns).to_have_attribute('data-manual', 'true')
                            dns.locator('summary').first.click()
                            expect(dns.locator('.manual-guidance')).to_be_visible()
                            page.locator('#check-status').select_option('unknown')
                            page.screenshot(path=str(out/f'{system}-{width}-manual.png'), full_page=True)
                            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                            assert not errors, errors
                            results.append({'system': system, 'width': width, 'simulatedChanges': writes, 'productionWrites': False, 'checks': 'passed'})
                        finally:
                            context.close()
                            server.shutdown()
                            server.server_close()
                            thread.join()
        finally:
            browser.close()
    (out/'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(results, ensure_ascii=False))


if __name__ == '__main__':
    main()
