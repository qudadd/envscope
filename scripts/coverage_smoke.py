"""Offline task acceptance for coverage, encrypted archives and temporary browser."""
import json
import shutil
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock, patch
from playwright.sync_api import sync_playwright, expect

from envscope.accounts import AccountManager
from envscope import __release__
from envscope.dmg_archive import DmgArchive
from tests.test_dmg_archive import FakeImages
from envscope.browser import environment_finding
from envscope.environment_info import device_finding
from envscope.isolated_browser import IsolatedBrowser
from envscope.legacy import LegacyBridge
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture, target


def main():
    out = Path('artifacts/coverage-ui');out.mkdir(parents=True,exist_ok=True)
    results = {}
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        try:
            for width in (1024,1280,1440):
                with tempfile.TemporaryDirectory() as directory:
                    home = Path(directory).resolve()
                    store = StateStore(memory=True)
                    preferences = target('Windows',usage='web',usage_country='JP')
                    preferences.pop('environment_confirmed',None)
                    store.save_settings(preferences,confirm_environment=True)
                    store.complete_learning(1)
                    manager = AccountManager(home/'state',home/'profile')
                    manager.accounts_dir.mkdir(parents=True)
                    (manager.state_dir/manager.current_filename).write_text('A')
                    manager.data_dir.mkdir()
                    source = manager.accounts_dir/'B';source.mkdir()
                    (source/'fixture.txt').write_text('PRIVATE_SESSION_FIXTURE')
                    no_legacy = Mock(side_effect=AssertionError('Do not run vendor code'))
                    operations = Operations(store,home,account_manager=manager,discoverer=lambda:[],legacy=LegacyBridge('Windows',home,runner=no_legacy),region_lookup=lambda params: {'state':'unavailable','reason':'离线夹具'})
                    executable = home/'fake-browser';executable.write_text('NOT_EXECUTABLE')
                    process = Mock();process.poll.return_value=None
                    launcher = Mock(return_value=process)
                    operations.isolated_browser = IsolatedBrowser(home,'Windows',lambda:[('Fixture Browser',executable)],launcher,lambda p:False)
                    def audit(*args,**kwargs):
                        return fixture(home,store.settings(),browser=kwargs.get('browser'))
                    fake_images = FakeImages(home)
                    operations.dmg_archives = DmgArchive(manager,home/'dmg-work',system='Darwin',disk=fake_images)
                    server = make_server(store=store,operations=operations,auditor=audit)
                    thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    context = browser.new_context(viewport={'width':width,'height':900},locale='zh-CN')
                    page = context.new_page();errors=[]
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.on('dialog',lambda d:d.accept())
                    page.add_init_script('window.RTCPeerConnection=undefined;')
                    page.route('https://**/*',lambda r:r.abort())
                    try:
                        page.goto(f'http://127.0.0.1:{server.server_port}',wait_until='networkidle')
                        expect(page.locator('#app-version')).to_have_text(__release__)
                        if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                        page.locator('#start').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=30000)
                        page.locator('[data-page="coverage"]').click()
                        expect(page.locator('[data-dimension]')).to_have_count(8)
                        expect(page.locator('[data-feature]')).to_have_count(29)
                        expect(page.locator('[data-feature="components"]')).to_contain_text('原生实现')
                        expect(page.locator('[data-feature="system-network"]')).to_contain_text('原生实现')
                        expect(page.locator('[data-feature="client-repair"]')).to_contain_text('原生实现')
                        expect(page.locator('[data-feature="application-language"]')).to_contain_text('Windows 提供手动步骤')
                        page.locator('[data-dimension="device"]>summary').click()
                        expect(page.locator('[data-dimension="device"]')).to_contain_text('当前浏览器环境资料')
                        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                        page.screenshot(path=str(out/f'{width}-coverage.png'),full_page=True)
                        page.locator('[data-dimension="device"] button').first.click()
                        expect(page.locator('[data-inspection="device.environment"]')).to_be_visible()
                        page.locator('[data-page="accounts"]').click()
                        page.locator('#encrypted-slot').fill('B')
                        page.locator('#encrypted-path').fill(str(home/'fixture.envsnap'))
                        page.locator('#encrypted-password').fill('fixture-ui-password-123')
                        page.locator('#encrypted-export').click()
                        expect(page.locator('#account-output')).to_contain_text('已校验并导出',timeout=20000)
                        expect(page.locator('#encrypted-password')).to_have_value('')
                        assert b'PRIVATE_SESSION_FIXTURE' not in (home/'fixture.envsnap').read_bytes()
                        page.locator('#encrypted-slot').fill('C')
                        page.locator('#encrypted-password').fill('incorrect-password-fixture')
                        page.locator('#encrypted-import').click()
                        expect(page.locator('#account-output')).to_contain_text('密码不正确或存档已损坏',timeout=20000)
                        assert not (manager.accounts_dir/'C').exists()
                        page.locator('#encrypted-password').fill('fixture-ui-password-123')
                        page.locator('#encrypted-import').click()
                        expect(page.locator('#account-output')).to_contain_text('已校验并导入',timeout=20000)
                        assert (manager.accounts_dir/'C/fixture.txt').read_bytes()==(source/'fixture.txt').read_bytes()
                        expect(page.locator('#encrypted-password')).to_have_value('')
                        assert 'PRIVATE_SESSION_FIXTURE' not in page.locator('body').inner_text()
                        page.screenshot(path=str(out/f'{width}-archives.png'))
                        page.locator('#encrypted-format').select_option('dmg')
                        expect(page.locator('#encrypted-path')).to_have_value('')
                        page.locator('#encrypted-slot').fill('B')
                        page.locator('#encrypted-path').fill(str(home/'fixture.dmg'))
                        page.locator('#encrypted-password').fill('fixture-dmg-password-123')
                        page.locator('#encrypted-export').click()
                        expect(page.locator('#account-output')).to_contain_text('已校验并导出',timeout=20000)
                        page.locator('#encrypted-slot').fill('D')
                        page.locator('#encrypted-password').fill('fixture-dmg-password-123')
                        page.locator('#encrypted-import').click()
                        expect(page.locator('#account-output')).to_contain_text('槽位不匹配',timeout=20000)
                        assert not (manager.accounts_dir/'D').exists()
                        shutil.rmtree(source)
                        page.locator('#encrypted-slot').fill('B')
                        fake_images.fail_detach=True
                        page.locator('#encrypted-password').fill('fixture-dmg-password-123')
                        page.locator('#encrypted-import').click()
                        expect(page.locator('#encrypted-recovery')).to_be_visible(timeout=20000)
                        page.screenshot(path=str(out/f'{width}-dmg-recovery.png'))
                        fake_images.fail_detach=False
                        page.locator('#encrypted-cleanup').click()
                        expect(page.locator('#encrypted-recovery')).to_be_hidden(timeout=20000)
                        page.locator('#encrypted-password').fill('fixture-dmg-password-123')
                        page.locator('#encrypted-import').click()
                        expect(page.locator('#account-output')).to_contain_text('已校验并导入',timeout=20000)
                        expect(page.locator('#encrypted-password')).to_have_value('')
                        assert (source/'fixture.txt').read_bytes()==(manager.accounts_dir/'C/fixture.txt').read_bytes()
                        page.locator('[data-page="tools"]').click()
                        page.locator('#maintenance-action').select_option('open-safe')
                        expect(page.locator('#maintenance-run')).to_be_enabled()
                        page.locator('#maintenance-run').click()
                        expect(page.locator('#tool-output')).to_contain_text('临时浏览器已提交启动',timeout=20000)
                        launcher.assert_called_once()
                        process.poll.return_value=0
                        page.locator('#browser-cleanup').click()
                        expect(page.locator('#tool-output')).to_contain_text('已清理 1 个')
                        assert not errors,errors
                        no_legacy.assert_not_called()
                        results[str(width)]={'portrait_dimensions':8,'features':28,'archive_roundtrip':True,'dmg_fixture_roundtrip':True,'dmg_mismatch_rejected':True,'dmg_cleanup_recovery':True,'wrong_password_no_import':True,'password_cleared':True,'browser_launcher':'fixture-only','real_browser_or_account_launches':0,'page_errors':errors}
                    except Exception:
                        page.screenshot(path=str(out/f'{width}-failure.png'))
                        print(json.dumps({'page_errors':errors,'format':page.locator('#encrypted-format').evaluate('(e)=>e.outerHTML'),'visible_text':page.locator('main').inner_text()[-5000:]},ensure_ascii=False))
                        raise
                    finally:
                        context.close();server.shutdown();server.server_close();thread.join(timeout=3)
        finally:
            browser.close()
    (out/'summary.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(results,ensure_ascii=False))


if __name__=='__main__':
    main()
