"""Offline interaction acceptance; all external traffic and OS effects are fixtures."""
import json
from pathlib import Path
import tempfile
import threading
from zipfile import ZipFile

from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect, sync_playwright
from envscope.client_repair import ClientRepair
from envscope.guide import LESSON_VERSION
from envscope.legacy import LegacyBridge
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import target, fixture
from tests.test_client_repair import ClientFixture


def main():
    output=Path('artifacts/check-preferences-ui');output.mkdir(parents=True,exist_ok=True)
    results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        try:
            for system,width in (('Windows',1024),('Windows',1440),('Darwin',1024),('Darwin',1440)):
                with tempfile.TemporaryDirectory() as directory:
                    home=Path(directory).resolve();store=StateStore(home/'state');store.complete_learning(LESSON_VERSION)
                    values=target(system,'desktop','tun',client='flclash',usage_country='US')
                    store.save_settings({k:v for k,v in values.items() if k!='environment_confirmed'},confirm_environment=True)
                    io=ClientFixture(home,system);io.app.update(mode='flclash',label='FlClash');io.running=False
                    original=io.preference.read_bytes();seconds=[0]
                    client=ClientRepair(store,io,clock=lambda:seconds[0],sleeper=lambda n:seconds.__setitem__(0,seconds[0]+n))
                    calls=[]
                    def auditor(*args,**kwargs):
                        calls.append(kwargs.get('selected_checks'))
                        return fixture(home,kwargs['baseline_config'],system)
                    ops=Operations(store,home,legacy=LegacyBridge(platform_name=system,home=home),
                                   discoverer=lambda:[],client_repair=client)
                    server=make_server(store=store,operations=ops,auditor=auditor)
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    context=browser.new_context(viewport={'width':width,'height':950},locale='zh-CN',accept_downloads=True)
                    page=context.new_page();errors=[];outbound=[]
                    page.on('pageerror',lambda error:errors.append(str(error)))
                    context.add_init_script('''window.fixtureICE=0;window.RTCPeerConnection=class{
                      constructor(){window.fixtureICE++;}createDataChannel(){}close(){}
                      async createOffer(){return {};}async setLocalDescription(){this.onicecandidate?.({candidate:null});}};''')
                    def external(route):
                        outbound.append(route.request.url)
                        ip='2001:4860:4860::8888' if 'api6' in route.request.url else '8.8.8.8'
                        body='ip='+ip+'\nloc=US' if '/trace' in route.request.url else json.dumps({'ip':ip})
                        route.fulfill(status=200,body=body,headers={'Access-Control-Allow-Origin':'*'})
                    page.route('https://**/*',external)
                    try:
                        page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                        open_page(page, 'settings')
                        page.locator('[name=optional][value=webrtc]').uncheck()
                        page.locator('[name=optional][value=ecosystem]').uncheck()
                        page.locator('#optional-failures').check()
                        page.locator('#check-preferences-form button[type=submit]').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=45000)
                        expect(page.locator('#check-preferences-output')).to_contain_text('已保存')
                        page.wait_for_function("document.querySelector('#workspace').dataset.state==='complete'")
                        assert calls and all('extra.ecosystem' not in selected and 'udp.stun' not in selected for selected in calls)
                        assert page.evaluate('window.fixtureICE')==0
                        open_page(page, 'checks')
                        expect(page.locator('#all-checks-context')).to_contain_text('本次检测')
                        rows={f['id']:f for f in server.last_raw_report['findings']}
                        assert rows['extra.ecosystem']['status']=='skipped' and rows['udp.stun']['status']=='skipped'
                        expect(page.locator('[data-inspection="extra.ecosystem"]')).to_contain_text('未勾选 · 未检测')
                        expect(page.locator('[data-inspection="udp.stun"]')).to_contain_text('未勾选 · 未检测')
                        page.locator('#checks-select-all').click()
                        expect(page.locator('#checks-selected-count')).to_contain_text('57')
                        page.locator('#checks-preferences').click()
                        expect(page.locator('#check-preferences-form')).to_be_visible()
                        # ZIP download is a user action. It cannot include any raw fixture secrets.
                        with page.expect_download() as pending:page.locator('#diagnostics-export').click()
                        downloaded=pending.value;path=Path(downloaded.path())
                        with ZipFile(path) as archive:
                            assert set(archive.namelist())=={'summary.json','commands.jsonl','README.txt'}
                            content=b''.join(archive.read(name) for name in archive.namelist())
                            assert b'8.8.8.8' not in content and b'FIXTURE_ONLY' not in content and str(home).encode() not in content
                            assert json.loads(archive.read('summary.json'))['counts']['skipped']>0
                        page.locator('#diagnostic-logging').uncheck()
                        page.locator('#check-preferences-form button[type=submit]').click()
                        expect(page.locator('#diagnostic-log-state')).to_contain_text('已关闭')
                        before=len(calls)
                        page.reload(wait_until='networkidle')
                        open_page(page, 'settings')
                        expect(page.locator('[name=optional][value=webrtc]')).not_to_be_checked()
                        expect(page.locator('[name=optional][value=ecosystem]')).not_to_be_checked()
                        expect(page.locator('#optional-failures')).to_be_checked()
                        expect(page.locator('#diagnostic-logging')).not_to_be_checked()
                        assert len(calls)==before
                        # A fresh audit after reload; old evidence is not used for a client action.
                        open_page(page, 'audit');page.locator('#start').click()
                        expect(page.locator('#start')).to_be_enabled(timeout=45000)
                        open_page(page, 'upkeep');page.locator('#client-load').click()
                        expect(page.locator('#client-app')).to_contain_text('FlClash')
                        expect(page.locator('#client-tun')).to_be_disabled()
                        expect(page.locator('#client-policy')).to_have_class('note manual-guidance')
                        page.screenshot(path=str(output/f'{system}-{width}-client.png'),full_page=True)
                        assert io.preference.read_bytes()==original and not io.calls
                        open_page(page, 'settings')
                        page.screenshot(path=str(output/f'{system}-{width}-preferences.png'),full_page=True)
                        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                        assert not errors,errors
                        results.append({'system':system,'width':width,'checks':'passed','persisted':True,
                                        'disabledICERequests':0,'zipWhitelist':True,'productionWrites':False})
                    finally:
                        context.close();server.shutdown();server.server_close();thread.join(timeout=3)
        finally:browser.close()
    (output/'results.json').write_bytes(json.dumps(results,ensure_ascii=False,indent=2).encode())
    print(json.dumps(results,ensure_ascii=False))


if __name__=='__main__':main()
