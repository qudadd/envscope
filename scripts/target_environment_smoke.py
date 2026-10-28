"""Target-first UI acceptance with only fixture network and disposable files."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock

from playwright.sync_api import expect, sync_playwright
from envscope.legacy import LegacyBridge
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from envscope.model import utc_now
from scripts.environment_fixtures import fixture, target, PROXY


def main():
    out = Path('artifacts/target-environment')
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            for width in (1024, 1280, 1440):
                with tempfile.TemporaryDirectory() as directory:
                    home = Path(directory)
                    fixture(home, target())
                    code = home / '.claude/settings.json'
                    original = b'{"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"},"permissions":{"deny":["Read(.env)"]},"mcpServers":{"fixture":{"env":{"SECRET":"PRIVATE_FIXTURE"}}},}'
                    code.write_bytes(original)
                    store = StateStore(home / 'state')
                    inventory = {'platform':'Windows','release':'11','locale':'zh-CN','network':{'timezone_id':'China Standard Time'}}
                    legacy = LegacyBridge(home=home, runner=Mock(side_effect=AssertionError('No vendor execution')))
                    ops = Operations(store, home, legacy=legacy, discoverer=lambda: [], environment_reader=lambda: inventory)
                    ops.config_remedies.environ = {}
                    calls = []
                    def auditor(*args, **kwargs):
                        calls.append(kwargs['baseline_config'])
                        return fixture(home, kwargs['baseline_config'])
                    server = make_server(store=store, operations=ops, auditor=auditor)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    origin = 'http://127.0.0.1:' + str(server.server_port)
                    context = browser.new_context(viewport={'width':width,'height':950}, locale='zh-CN')
                    page = context.new_page()
                    errors, outbound = [], []
                    page.on('pageerror', lambda e: errors.append(str(e)))
                    page.add_init_script('window.RTCPeerConnection=undefined;')
                    def block(route):
                        outbound.append(route.request.url)
                        route.abort()
                    page.route('https://**/*', block)
                    try:
                        page.goto(origin, wait_until='networkidle')
                        page.locator('#learning-skip').click()
                        expect(page.locator('#target-form')).to_be_visible()
                        expect(page.locator('#target-confirm')).to_be_enabled()
                        page.locator('#start').click()
                        assert not calls and not outbound and code.read_bytes() == original
                        token = context.request.get(origin+'/api/session').json()['token']
                        snapshot = {'schema_version':1,'kind':'envscope-browser-observations','contains_sensitive':True,
                                    'created_at':utc_now(),'http':[],'ice':[],'ice_complete':False}
                        denied = context.request.post(origin+'/api/audit', data={'snapshot':snapshot}, headers={'Origin':origin,'X-EnvScope-Token':token})
                        assert denied.status == 409 and not calls
                        page.locator('#target-form [name=usage]').select_option('cli')
                        page.locator('#target-form [name=connection_mode]').select_option('direct')
                        expect(page.locator('#target-form [name=timezone]')).to_have_value('China Standard Time')
                        expect(page.locator('#target-form [name=locale]')).to_have_value('zh-CN')
                        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                        page.screenshot(path=str(out/f'{width}-setup.png'), full_page=True)
                        page.locator('#target-confirm').click()
                        expect(page.locator('#apply-solution')).to_be_visible()
                        expect(page.locator('#verdict')).to_contain_text('不合格')
                        assert code.read_bytes() == original
                        page.locator('#apply-solution').click()
                        expect(page.locator('#verdict')).to_have_text('所选目标的环境检查合格')
                        expect(page.locator('#resolution')).to_contain_text('1 / 1')
                        expect(page.locator('#desktop-handoff')).to_be_hidden()
                        repaired = code.read_bytes()
                        assert json.loads(repaired)['env']['NODE_TLS_REJECT_UNAUTHORIZED'] == '1'
                        assert json.loads(repaired)['mcpServers']['fixture']['env']['SECRET'] == 'PRIVATE_FIXTURE'
                        assert 'PRIVATE_FIXTURE' not in page.locator('body').inner_text()
                        page.evaluate('window.scrollTo(0,0)')
                        page.screenshot(path=str(out/f'{width}-qualified.png'))
                        previous_count = len(calls)
                        page.reload(wait_until='networkidle')
                        expect(page.locator('#learning-panel')).to_be_hidden()
                        expect(page.locator('#target-form')).to_be_hidden()
                        page.locator('#start').click()
                        expect(page.locator('#verdict')).to_have_text('所选目标的环境检查合格')
                        assert len(calls) == previous_count + 1
                        expect(page.locator('#apply-solution')).to_have_count(0)
                        page.locator('#target-edit').click()
                        expect(page.locator('#target-confirm')).to_be_enabled()
                        page.locator('#target-form [name=connection_mode]').select_option('http_proxy')
                        page.locator('#target-form [name=target_proxy]').fill(PROXY)
                        page.locator('#target-cancel').click()
                        assert store.settings()['connection_mode'] == 'direct'
                        page.locator('#target-edit').click()
                        expect(page.locator('#target-confirm')).to_be_enabled()
                        page.locator('#target-form [name=usage]').select_option('web')
                        page.locator('#target-confirm').click()
                        expect(page.locator('#target-form')).to_be_hidden()
                        expect(page.locator('#target-summary')).to_contain_text('网页版')
                        expect(page.locator('#verdict')).to_have_text('所选目标的环境检查合格')
                        assert code.read_bytes() == repaired, 'web selection must not rewrite Code'
                        assert store.settings()['usage'] == 'web'
                        page.locator('[data-page=checks]').click()
                        row = page.locator('[data-inspection="extra.cli_paths"]')
                        expect(row).to_contain_text('不适用')
                        page.locator('#check-status').select_option('excluded')
                        expect(page.locator('[data-inspection="dns.leak"]')).to_contain_text('本版未支持')
                        assert not errors, errors
                        results[str(width)] = {'first_use_gate':True,'api_gate':True,'preserve_timezone_locale':True,
                                               'repair_recheck':True,'private_fields_preserved':True,'repeat_without_setup':True,
                                               'cancel_no_change':True,'change_usage_scope':True,'unknown_not_privacy_pass':True,
                                               'page_errors':errors,'overflow':False,'real_network_or_account_changes':False}
                    finally:
                        context.close()
                        server.shutdown();server.server_close();thread.join(3)
        finally:
            browser.close()
    (out/'result.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__':
    main()
