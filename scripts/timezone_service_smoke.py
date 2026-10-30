"""Offline UI walkthrough; administrator authorization is an injected fixture."""
import json
from pathlib import Path
import tempfile
import threading
import time
from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect,sync_playwright

from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from envscope.timezone_service import TimezoneService
from scripts.environment_fixtures import fixture,target
from tests.test_timezone_integration import TransactionFixture


def main():
    output=Path('artifacts/timezone-ui');output.mkdir(parents=True,exist_ok=True)
    evidence=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for width in (1024,1280,1440):
            with tempfile.TemporaryDirectory() as temp:
                home=Path(temp).resolve();store=StateStore(memory=True)
                settings=target('Darwin','desktop','tun',usage_country='US',country='US',region_profile='us-new-york',timezone='America/New_York',locale='en-US')
                store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
                store.complete_learning(1)
                world={'platform':'Darwin','timezone_iana':'Asia/Shanghai','locale':'en-US'}
                ops=Operations(store,home,discoverer=lambda:[],environment_reader=lambda:world,region_lookup=lambda _: {'state':'unavailable','reason':'离线夹具'})
                io=TransactionFixture(world);io.clock=time.time
                ops.timezone_service=TimezoneService(store,lambda:world,system='Darwin',io=io,uid=501)
                auditor=lambda *args,**kwargs:fixture(home,store.settings(),'Darwin',browser=kwargs.get('browser'))
                server=make_server(store=store,operations=ops,auditor=auditor)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context=browser.new_context(viewport={'width':width,'height':1000},locale='zh-CN')
                page=context.new_page();errors=[]
                page.on('pageerror',lambda err:errors.append(str(err)))
                page.on('dialog',lambda dialog:dialog.accept())
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*',lambda request:request.abort())
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('#start').click();expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-state')).to_have_text('尚未授权')
                    page.locator('#timezone-service-prepare').click()
                    expect(page.locator('#timezone-service-plan')).to_contain_text('Asia/Shanghai 配置为 America/New_York')
                    assert not io.scripts
                    page.locator('#timezone-service-panel').screenshot(path=str(output/f'{width}-preview.png'))
                    page.locator('#timezone-service-plan button').click()
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-state')).to_have_text('系统时区守护正常',timeout=10000)
                    assert len(io.scripts)==1
                    page.locator('#timezone-service-undo').click()
                    expect(page.locator('#timezone-service-plan')).to_contain_text('Asia/Shanghai')
                    page.locator('#timezone-service-plan button').click()
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-state')).to_have_text('尚未授权')
                    assert world['timezone_iana']=='Asia/Shanghai'
                    page.locator('#timezone-service-prepare').click()
                    page.locator('#timezone-service-plan button').click()
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-state')).to_have_text('系统时区守护正常')
                    io.interrupt=True
                    page.locator('#timezone-service-prepare').click()
                    expect(page.locator('#timezone-service-plan button')).to_be_visible()
                    page.locator('#timezone-service-plan button').click()
                    expect(page.locator('#timezone-service-state')).to_have_text('上次操作需恢复',timeout=10000)
                    expect(page.locator('#timezone-service-status')).to_have_class('note manual-guidance')
                    page.locator('#timezone-service-panel').screenshot(path=str(output/f'{width}-recovery.png'))
                    io.interrupt=False
                    page.locator('#timezone-service-recover').click()
                    expect(page.locator('#timezone-service-plan')).to_contain_text('恢复上次保存的服务文件')
                    page.locator('#timezone-service-plan button').click()
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-state')).to_have_text('系统时区守护正常')
                    page.locator('#timezone-service-restore').check()
                    page.locator('#timezone-service-stop').click()
                    expect(page.locator('#timezone-service-plan')).to_contain_text('恢复安装前的系统时区：Asia/Shanghai')
                    page.locator('#timezone-service-plan button').click()
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-state')).to_have_text('尚未授权')
                    ops.timezone_service.system='Windows'
                    page.reload(wait_until='networkidle');open_page(page, 'upkeep')
                    expect(page.locator('#timezone-service-panel')).to_be_hidden()
                    assert not errors,errors
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    evidence.append({'width':width,'preview_before_authorization':True,'installed_fixture':True,'committed_undo':True,'interruption_and_recovery':True,'uninstall_preview_and_restore':True,'hidden_on_windows':True,'page_errors':errors,'real_system_changes':False,'actual_admin_dialogs':0})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(timeout=3)
        browser.close()
    (output/'result.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
    print(json.dumps(evidence))


if __name__=='__main__':main()
