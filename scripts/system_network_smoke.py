"""Offline desktop walkthrough. No OS network write, elevation or public probe."""
import json
from pathlib import Path
import tempfile
import threading
from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect,sync_playwright

from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from envscope.system_network import SystemNetwork
from scripts.environment_fixtures import fixture,target
from tests.test_system_network import NetworkFixture


class InterruptedFixture(NetworkFixture):
    interrupt=False
    def execute(self,action,payload):
        super().execute(action,payload)
        if action=='apply' and self.interrupt:
            self.record['state']='prepared'
            raise ValueError('隔离夹具：写入后进程中断。原备份保留，先预览恢复。')


def main():
    output=Path('artifacts/system-network-ui');output.mkdir(parents=True,exist_ok=True)
    evidence=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system,width in (('Windows',1024),('Darwin',1280),('Windows',1440)):
            with tempfile.TemporaryDirectory() as folder:
                home=Path(folder).resolve();store=StateStore(memory=True)
                values=target(system,'desktop','tun',usage_country='US',ipv6_mode='disabled')
                store.save_settings({k:v for k,v in values.items() if k!='environment_confirmed'},confirm_environment=True)
                store.complete_learning(1);io=InterruptedFixture();original=io.snapshot()
                network=SystemNetwork(store,io)
                ops=Operations(store,home,network=network,discoverer=lambda:[],environment_reader=lambda:{'platform':system},
                               region_lookup=lambda _: {'state':'unavailable','reason':'离线夹具'})
                audits=[]
                def audit(*args,**kwargs):
                    audits.append(True)
                    disabled=all(not row['ipv6_enabled'] for row in io.snapshot()['adapters'])
                    return fixture(home,store.settings(),system,fault='ipv6_disabled' if disabled else None,browser=kwargs.get('browser'))
                server=make_server(store=store,operations=ops,auditor=audit)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context=browser.new_context(viewport={'width':width,'height':1000},locale='zh-CN')
                page=context.new_page();errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*',lambda request:request.abort())
                def upkeep():
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('#start').click();upkeep()
                    expect(page.locator('#network-state')).to_have_text('尚无修改记录')
                    page.locator('#network-load').click()
                    boxes=page.locator('#network-adapters input')
                    expect(boxes).to_have_count(2);expect(boxes.nth(0)).to_be_checked();expect(boxes.nth(1)).not_to_be_checked()
                    page.locator('#network-all').click();expect(boxes.nth(1)).to_be_checked()
                    page.locator('#network-none').click();expect(boxes.nth(0)).not_to_be_checked()
                    page.locator('#network-all').click();page.locator('#network-dns').check()
                    page.locator('#network-prepare').click()
                    expect(page.locator('#network-plan')).to_contain_text('缓存内容不能撤销')
                    expect(page.locator('#network-plan')).to_contain_text('Inactive')
                    assert not io.calls
                    page.locator('#network-panel').screenshot(path=str(output/f'{width}-preview.png'))
                    page.locator('#network-dns').uncheck();expect(page.locator('#network-plan')).to_be_empty()
                    page.locator('#network-dns').check();page.locator('#network-prepare').click()
                    page.locator('#network-plan button').click()
                    expect(page.locator('#network-state')).to_have_text('上次设置已读回',timeout=15000)
                    upkeep();assert len(audits)>=2 and len(io.calls)==1
                    expect(page.locator('#network-adapters')).to_contain_text('IPv6 已关闭')
                    assert next(f for f in server.last_raw_report['findings'] if f['id']=='target.ipv6')['status']=='pass'
                    page.locator('#network-restore').click()
                    expect(page.locator('#network-plan')).to_contain_text('只恢复最新事务')
                    page.locator('#network-plan button').click()
                    expect(page.locator('#network-state')).to_have_text('已恢复原设置',timeout=15000)
                    upkeep();assert io.snapshot()==original
                    expect(page.locator('#network-adapters')).to_contain_text('IPv6 已启用')
                    io.interrupt=True
                    page.locator('#network-prepare').click();expect(page.locator('#network-plan button')).to_be_visible()
                    page.locator('#network-plan button').click()
                    expect(page.locator('#network-state')).to_have_text('上次操作未完成',timeout=15000)
                    upkeep();expect(page.locator('#network-prepare')).to_be_disabled()
                    expect(page.locator('#network-restore')).to_be_enabled()
                    expect(page.locator('#network-status')).to_have_class('note manual-guidance')
                    page.locator('#network-panel').screenshot(path=str(output/f'{width}-recovery.png'))
                    io.interrupt=False
                    page.locator('#network-restore').click();page.locator('#network-plan button').click()
                    expect(page.locator('#network-state')).to_have_text('已恢复原设置',timeout=15000)
                    upkeep();assert io.snapshot()==original
                    assert not errors,errors
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    evidence.append({'platform':system,'width':width,'fixture':True,'select_all_and_clear':True,
                                     'preview_before_write':True,'input_change_invalidates_preview':True,'auto_retest':True,
                                     'configuration_readback':True,'interruption_visible':True,'original_restored':True,
                                     'actual_admin_dialogs':0,'real_network_changed':False,'page_errors':errors})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(timeout=3)
        browser.close()
    (output/'result.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
    print(json.dumps(evidence))


if __name__=='__main__':main()
