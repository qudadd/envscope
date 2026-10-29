"""Account recovery UI with temporary identities and injected process callbacks."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright
from envscope.accounts import AccountManager, _manifest
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture, target


class Interrupted(BaseException):
    pass


def main():
    output = Path('artifacts/account-recovery-ui'); output.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        for system, boundary in [('Windows', 'staged'), ('Darwin', 'committed')]:
            with tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp).resolve(); state, data = home/'accounts-state', home/'Claude'
                (state/'accounts/B').mkdir(parents=True); data.mkdir()
                (data/'Local State').write_bytes(b'A-fixture-device')
                (state/'accounts/B/Local State').write_bytes(b'B-fixture-device')
                (state/'current.txt').write_text('A')
                events = []
                manager = AccountManager(state, data, 'current.txt', lambda: events.append('exit') or True,
                                         lambda: events.append('launch') or True)
                import envscope.accounts as account_module
                writer = account_module._atomic_text
                def interrupt(path, text):
                    writer(path, text)
                    if path == manager.journal_file and json.loads(text)['state'] == boundary:
                        raise Interrupted()
                with patch.object(account_module, '_atomic_text', side_effect=interrupt):
                    try:
                        manager.switch('B', lambda: True)
                    except Interrupted:
                        pass
                    else:
                        raise AssertionError('Fixture did not interrupt the exchange')
                assert events == ['exit']
                store = StateStore(home/'settings')
                settings = target(system, 'desktop', 'direct', usage_country='US', country='US')
                store.save_settings({k:v for k,v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
                operations = Operations(store, home, account_manager=manager, discoverer=lambda: [],
                                        region_lookup=lambda _: {'state':'unavailable','reason':'fixture'},
                                        environment_reader=lambda: {'platform': system})
                server = make_server(store=store, operations=operations, auditor=lambda *a, **k: fixture(home, settings, system))
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                context = browser.new_context(viewport={'width':1280,'height':950})
                page = context.new_page(); errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*', lambda route: route.abort())
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port), wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible(): page.locator('#learning-skip').click()
                    page.locator('.tab[data-page=accounts]').click()
                    expect(page.locator('#account-recovery')).to_be_visible()
                    expect(page.locator('[data-account=B] button').first).to_be_disabled()
                    before = _manifest(state), _manifest(data)
                    page.locator('#account-recovery-check').click()
                    expect(page.locator('#account-recovery-plan')).to_contain_text('不删除')
                    assert before == (_manifest(state), _manifest(data)) and events == ['exit']
                    expect(page.locator('#account-recovery-confirm')).to_be_enabled()
                    page.locator('#page-accounts').screenshot(path=str(output/(system+'-review.png')))
                    page.locator('#account-recovery-confirm').click()
                    expect(page.locator('#account-output')).to_contain_text('账号资料已恢复并核验')
                    expect(page.locator('#account-recovery')).not_to_be_visible()
                    expect(page.locator('[data-account=B] button').first).to_be_enabled()
                    expected = 'B' if boundary == 'committed' else 'A'
                    assert (data/'Local State').read_bytes() == (expected+'-fixture-device').encode()
                    assert manager._read_current() == expected and not manager._pending()
                    assert events == ['exit','exit'] and not errors
                    results.append({'system':system,'mode':'finish' if boundary=='committed' else 'rollback',
                                    'reviewed':True,'whole_identity_verified':True,'launched':False,
                                    'real_accounts_changed':False,'page_errors':errors})
                finally:
                    context.close(); server.shutdown(); server.server_close(); thread.join(3)
        browser.close()
    (output/'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__': main()
