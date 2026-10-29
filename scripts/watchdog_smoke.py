"""Reviewed Watchdog setup and drift repair in a disposable OS adapter."""
import json
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import expect,sync_playwright
from envscope.maintenance import Maintenance
from envscope.operations import Operations
from envscope.state import StateStore
from envscope.watchdog import Watchdog
from envscope.service import make_server
from scripts.environment_fixtures import fixture,target
from tests.test_maintenance import FakeScheduler


def main():
    out=Path('artifacts/watchdog-ui');out.mkdir(parents=True,exist_ok=True)
    results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system in ('Windows','Darwin'):
            with tempfile.TemporaryDirectory() as temp:
                home=Path(temp).resolve();store=StateStore(home/'state')
                zone='Eastern Standard Time' if system=='Windows' else 'America/New_York'
                locale='en-US' if system=='Windows' else 'en_US'
                settings=target(system,'desktop','direct',usage_country='US',country='US',timezone=zone,locale=locale,region_profile='us-new-york')
                store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
                store._write('learning.private.json',{'completed':True,'version':1})
                inventory={'platform':system,'locale':locale,'network':{'timezone_id':zone}};writes=[]
                def writer(key,value):
                    writes.append((key,value))
                    if key=='timezone':inventory['network']['timezone_id']=value
                    else:inventory[key]=value
                guard=Watchdog(home,system,reader=lambda:inventory,writer=writer,clients=lambda:[])
                auditor=lambda *args,**kwargs:fixture(home,kwargs.get('baseline_config') or store.settings(),system)
                maintenance=Maintenance(store,home=home,scheduler=FakeScheduler(),watchdog=guard,auditor=auditor)
                opened=[]
                ops=Operations(store,home,maintenance=maintenance,discoverer=lambda:[],environment_reader=lambda:inventory,remedy_opener=lambda action:opened.append(action) or True,
                    region_lookup=lambda params:{'state':'unavailable','reason':'离线夹具'})
                server=make_server(store=store,operations=ops,auditor=auditor)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context=browser.new_context(viewport={'width':1280,'height':950});page=context.new_page();errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.add_init_script('window.RTCPeerConnection=undefined;');page.route('https://**/*',lambda r:r.abort())
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('#start').click();expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    page.locator('.tab[data-page=upkeep]').click()
                    expect(page.locator('#upkeep-egress')).to_contain_text('尚无有效出口观测')
                    page.locator('#upkeep-guard-timezone').check()
                    page.locator('#upkeep-prepare').click();expect(page.locator('#upkeep-plan')).to_contain_text('保持时区')
                    assert not writes and not maintenance.scheduler.definition
                    page.locator('#upkeep-plan button').click()
                    expect(page.locator('#upkeep-state')).to_contain_text('等待')
                    inventory['network']['timezone_id']='China Standard Time' if system=='Windows' else 'Asia/Shanghai'
                    page.locator('#upkeep-run').click()
                    expect(page.locator('#upkeep-watchdog-state')).to_contain_text('已恢复',timeout=30000)
                    expect(page.locator('#upkeep-egress')).to_contain_text('不同出口集合 1 种')
                    assert writes==[('timezone',zone)]
                    expect(page.locator('#upkeep-events')).to_contain_text('漂移')
                    expect(page.locator('#upkeep-journal')).to_contain_text('完整事件日志')
                    page.locator('#upkeep-open-logs').click();expect(page.locator('#upkeep-output')).to_contain_text('已打开完整日志目录')
                    assert opened==['maintenance-logs']
                    page.screenshot(path=str(out/(system+'-restored.png')),full_page=True)
                    page.locator('#upkeep-stop').click();expect(page.locator('#upkeep-state')).to_contain_text('尚未启用')
                    assert not maintenance.scheduler.definition and not errors
                    assert list((maintenance.root/'events').glob('*.jsonl'))
                    results.append({'platform':system,'preview_before_write':True,'drift_restored_and_rechecked':True,'distinct_set_count_visible':True,'no_sample_is_not_a_pass':True,'durable_log':True,'stopped':True,'real_user_changes':False})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(3)
        browser.close()
    (out/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8');print(json.dumps(results))


if __name__=='__main__':main()
