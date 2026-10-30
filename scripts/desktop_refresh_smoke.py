"""Desktop navigation, retained inspection state, keyboard and visual fixtures."""
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import Mock

from playwright.sync_api import sync_playwright, expect
from envscope.guide import LESSON_VERSION
from envscope.state import StateStore
from envscope.operations import Operations
from envscope.legacy import LegacyBridge
from envscope.service import make_server
from scripts.environment_fixtures import fixture, target
from scripts.ui_navigation import open_page


def main():
    out=Path('artifacts/desktop-refresh');out.mkdir(parents=True,exist_ok=True);results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        try:
            for system in ('Windows','Darwin'):
                with tempfile.TemporaryDirectory() as folder:
                    home=Path(folder);store=StateStore(home/'state');store.complete_learning(LESSON_VERSION)
                    settings=target(system,'cli','direct',usage_country='US')
                    store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
                    ops=Operations(store,home,discoverer=lambda:[],legacy=LegacyBridge(platform_name=system,home=home,runner=Mock(side_effect=AssertionError('No vendor execution'))))
                    calls=[]
                    def audit(*args,**kwargs):
                        calls.append(1)
                        return fixture(home,kwargs['baseline_config'],system,'permission',browser=kwargs.get('browser'))
                    server=make_server(store=store,operations=ops,auditor=audit)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    try:
                        for width in (1024,1280,1440):
                            context=browser.new_context(viewport={'width':width,'height':900},locale='zh-CN',reduced_motion='reduce')
                            page=context.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                            page.add_init_script('window.RTCPeerConnection=undefined');page.route('https://**/*',lambda route:route.abort())
                            page.goto(f'http://127.0.0.1:{server.server_port}/');expect(page.locator('#target-edit')).to_be_enabled()
                            expect(page.locator('#all-checks-list details').first).to_be_attached(timeout=30000)
                            open_page(page,'checks');page.evaluate('window.scrollTo(0,650)')
                            open_page(page,'settings');open_page(page,'checks')
                            for _ in range(20):
                                if page.evaluate('window.scrollY > 600'):break
                                page.wait_for_timeout(50)
                            assert page.evaluate('window.scrollY > 600'),'Navigation lost the previous scroll position'
                            page.evaluate('window.scrollTo(0,0)')
                            row=page.locator('[data-inspection="baseline.timezone"]');row.locator('summary').click()
                            page.locator('#check-search').fill('时区');expect(row).to_have_attribute('open','')
                            page.locator('#check-search').fill('');expect(row).to_have_attribute('open','')
                            for name in ('audit','checks','upkeep','accounts','tools','history','settings','coverage'):
                                open_page(page,name)
                                if name=='upkeep':
                                    page.locator('#advanced-maintenance').evaluate('(n)=>n.open=false')
                                page.evaluate('window.scrollTo(0,0)')
                                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),(system,width,name,'horizontal overflow')
                                assert page.locator('.tab[aria-current="page"]').count()==1
                                page.screenshot(path=str(out/f'{system}-{width}-{name}.png'))
                            open_page(page,'audit');before=len(calls)
                            with page.expect_response(lambda response:response.url.endswith('/api/audit')) as received:
                                page.locator('#start').click();page.locator('#start').dispatch_event('click')
                            assert received.value.ok, received.value.text()
                            expect(page.locator('#start')).to_be_enabled(timeout=45000)
                            assert server.last_raw_report and server.last_raw_report.get('report_id'),'Audit must produce a report'
                            expect(page.locator('#session-state')).not_to_contain_text('系统检测未完成')
                            assert len(calls)==before+1,'Repeated click must not start a second audit'
                            page.screenshot(path=str(out/f'{system}-{width}-results.png'))
                            page.locator('#more-menu>summary').focus();page.keyboard.press('Enter')
                            expect(page.locator('#more-menu')).to_have_attribute('open','')
                            page.keyboard.press('Escape');expect(page.locator('#more-menu')).not_to_have_attribute('open','')
                            expect(page.locator('#more-menu>summary')).to_be_focused()
                            assert not errors,errors
                            results.append({'system':system,'width':width,'pages':8,'scroll_retained':True,'disclosure_retained':True,'duplicate_blocked':True,'keyboard':True,'errors':errors})
                            context.close()
                    finally:server.shutdown();server.server_close();thread.join(3)
        finally:browser.close()
    (out/'result.json').write_text(json.dumps(results,indent=2),encoding='utf-8');print(json.dumps(results))


if __name__=='__main__':main()
