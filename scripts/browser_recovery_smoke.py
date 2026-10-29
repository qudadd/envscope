"""Browser residual recovery UI; all profiles, PIDs and openers are fixtures."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock

from playwright.sync_api import expect,sync_playwright

from envscope.browser_sessions import MARKER
from envscope.isolated_browser import IsolatedBrowser
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture,target


def main():
    output=Path('artifacts/browser-recovery-ui');output.mkdir(parents=True,exist_ok=True)
    results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        try:
            for system,width in [('Windows',1024),('Windows',1280),('Darwin',1440)]:
                with tempfile.TemporaryDirectory(prefix='envscope-browser-ui-') as directory:
                    home=Path(directory).resolve();store=StateStore(home/'settings')
                    settings=target(system,'web','direct',usage_country='US')
                    store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
                    store.complete_learning(1)
                    executable=home/'not-executable-browser';executable.write_text('INERT_BROWSER_FIXTURE')
                    launcher,worker=Mock(),Mock();running=Mock(return_value=None)
                    temporary=IsolatedBrowser(home,system,lambda:[('Fixture',executable)],launcher,running,worker)
                    temporary.store.alive=Mock(return_value=None)
                    profile=temporary.store.create('a'*32)
                    (profile/'Cookies').write_bytes(b'FAKE_PRIVATE_NEW_COOKIE')
                    temporary.store.launched('a'*32,Mock(pid=2147483000))
                    legacy=temporary.root/('b'*32);legacy.mkdir();(legacy/'Cookies').write_bytes(b'FAKE_OLD_COOKIE')
                    malformed=temporary.root/('c'*32);malformed.mkdir();(malformed/MARKER).write_bytes(b'{INVALID')
                    (malformed/'keep').write_bytes(b'UNKNOWN_MUST_STAY')
                    opened=[]
                    operations=Operations(store,home,discoverer=lambda:[],remedy_opener=lambda action:opened.append(action) or True,
                        environment_reader=lambda:{'platform':system,'locale':'en-US','network':{'timezone_id':'UTC'}},
                        region_lookup=lambda params:{'state':'unavailable','reason':'Offline fixture'})
                    operations.isolated_browser=temporary
                    server=make_server(store=store,operations=operations,auditor=lambda *a,**k:fixture(home,store.settings(),system))
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    context=browser.new_context(viewport={'width':width,'height':950});page=context.new_page();errors=[]
                    page.on('pageerror',lambda error:errors.append(str(error)))
                    page.add_init_script('window.RTCPeerConnection=undefined;');page.route('https://**/*',lambda route:route.abort())
                    try:
                        page.goto(f'http://127.0.0.1:{server.server_port}',wait_until='networkidle')
                        if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                        page.locator('[data-page=tools]').click()
                        expect(page.locator('#browser-session-status')).to_contain_text('旧版资料 1 个')
                        expect(page.locator('#browser-session-status')).to_contain_text('无法核实 1 个')
                        page.once('dialog',lambda dialog:dialog.dismiss())
                        page.locator('#browser-cleanup').click()
                        assert profile.exists() and legacy.exists()
                        page.once('dialog',lambda dialog:dialog.accept())
                        page.locator('#browser-cleanup').click()
                        expect(page.locator('#tool-output')).to_contain_text('已清理 0 个',timeout=15000)
                        expect(page.locator('#tool-output')).to_contain_text('保留')
                        assert profile.exists() and legacy.exists()
                        running.return_value=False;temporary.store.alive.return_value=False
                        page.once('dialog',lambda dialog:dialog.accept())
                        page.locator('#browser-cleanup').click()
                        expect(page.locator('#tool-output')).to_contain_text('已清理 2 个',timeout=15000)
                        expect(page.locator('#browser-session-status')).to_contain_text('旧版资料 0 个')
                        expect(page.locator('#browser-session-status')).to_contain_text('无法核实 1 个')
                        expect(page.locator('#browser-session-status')).to_have_class('note manual-guidance')
                        assert not profile.exists() and not legacy.exists()
                        assert (malformed/'keep').read_bytes()==b'UNKNOWN_MUST_STAY'
                        page.locator('#browser-folder').click();expect(page.locator('#tool-output')).to_contain_text('已打开临时资料目录')
                        page.locator('#browser-logs').click();expect(page.locator('#tool-output')).to_contain_text('已打开清理记录')
                        assert opened==['browser-folder','browser-logs']
                        launcher.assert_not_called();worker.assert_not_called()
                        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                        assert 'FAKE_PRIVATE_NEW_COOKIE' not in page.locator('body').inner_text()
                        assert not errors,errors
                        expect(page.locator('#browser-cleanup')).to_be_enabled()
                        page.locator('#browser-cleanup').scroll_into_view_if_needed()
                        page.screenshot(path=str(output/f'{system}-{width}.png'))
                        results.append({'platform':system,'width':width,'cancel_preserves_profiles':True,'unknown_kept':True,
                            'restart_record_recovered':True,'legacy_confirmed_cleanup':True,'manual_links':True,
                            'no_horizontal_overflow':True,'real_browser_or_profile_used':False,'page_errors':errors})
                    finally:
                        context.close();server.shutdown();server.server_close();thread.join(3)
        finally:browser.close()
    (output/'results.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(results))


if __name__=='__main__':main()
