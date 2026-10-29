"""Offline UI exercise of review, selection, restore and automatic retest."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright, expect
from envscope.legacy_components import ComponentMigration
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import target, fixture
from tests.test_components import role


class JobsFixture:
    def __init__(self, system):
        self.system=system; self.rows=[role()]; self.receipt={'state':'not_configured','id':''}; self.calls=[]
        if system=='Darwin':
            self.rows[0].update(mode=0o644,group=20,label='local.claude-bodyguard')
            self.rows += [{**role(),'id':'timezone','title':'旧版时区守护','label':'local.tz-watchdog','enabled':False,'running':False,'mode':0o644,'group':20},
                         {**role(),'id':'update.user','title':'旧版用户更新任务','label':'local.claude-update','owned':False,'error':'permission_denied','reason':'隔离场景：读取被拒绝'}]
    def snapshot(self):return {'format':1,'system':self.system,'actor':'501','rows':deepcopy(self.rows)}
    def status(self):return deepcopy(self.receipt)
    def execute(self, action, payload):
        self.calls.append(action)
        if action=='retire':
            originals=[deepcopy(r) for r in self.rows if r['id'] in payload['roles']]
            self.receipt={'format':1,'state':'committed','id':payload['id'],'actor':'501','roles':payload['roles'],'original':originals}
            for row in self.rows:
                if row['id'] in payload['roles']:row.update(present=False,registered=False,enabled=False,running=False,definition=None,definition_sha=None,script_sha=None)
        else:
            for original in self.receipt['original']:
                self.rows[self.receipt['roles'].index(original['id'])]=deepcopy(original)
            self.receipt['state']='restored'


def main():
    out=Path('artifacts/components-ui');out.mkdir(parents=True,exist_ok=True);proof=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system,width in [('Windows',1024),('Darwin',1280)]:
            with tempfile.TemporaryDirectory() as folder:
                home=Path(folder).resolve();store=StateStore(home/'state');store.complete_learning(1)
                settings=target(system,'desktop','http_proxy',usage_country='US',country='US',target_proxy='http://127.0.0.1:7897')
                store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
                jobs=JobsFixture(system);components=ComponentMigration(store,home,io=jobs);audits=[]
                def auditor(*a,**k):audits.append(True);return fixture(home,store.settings(),system,browser=k.get('browser'))
                ops=Operations(store,home,components=components,discoverer=lambda:[],environment_reader=lambda:{'platform':system})
                server=make_server(store=store,operations=ops,auditor=auditor)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                page=browser.new_page(viewport={'width':width,'height':1000});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                page.add_init_script('window.RTCPeerConnection=undefined');page.route('https://**/*',lambda route:route.abort())
                def idle():expect(page.locator('#start')).to_be_enabled(timeout=30000)
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('.tab[data-page=upkeep]').click()
                    expect(page.locator('#components-state')).to_have_text('尚未迁移');idle()
                    expect(page.locator('#components-all')).to_be_checked()
                    page.locator('#components-all').uncheck();expect(page.locator('#components-prepare')).to_be_disabled()
                    page.locator('#components-all').check();page.locator('#components-prepare').click()
                    expect(page.locator('#components-plan')).to_contain_text('保护间隔');assert jobs.calls==[]
                    if system=='Darwin':
                        expect(page.locator('[data-role="update.user"]')).to_be_disabled()
                        expect(page.locator('#components-rows .manual-guidance')).to_contain_text('任务计划程序')
                        page.locator('[data-role="timezone"]').uncheck();expect(page.locator('#components-plan')).to_be_empty()
                        page.locator('[data-role="timezone"]').check();page.locator('#components-prepare').click()
                        expect(page.locator('#components-plan')).to_contain_text('保护间隔');idle()
                    page.locator('#components-panel').screenshot(path=str(out/(system+'-review.png')))
                    page.locator('#components-plan button').click()
                    expect(page.locator('#components-state')).to_contain_text('旧任务已移除',timeout=30000);idle()
                    assert audits and jobs.calls==['retire'];assert not components.conflict()
                    page.locator('#components-restore').click();expect(page.locator('#components-plan')).to_contain_text('RunAtLoad')
                    page.locator('#components-plan button').click()
                    expect(page.locator('#components-state')).to_have_text('已恢复原任务',timeout=30000);idle()
                    assert jobs.calls==['retire','restore'];assert len(audits)>=2;assert jobs.rows[0]['running'] is True
                    if system=='Darwin':assert jobs.rows[1]['enabled'] is False and jobs.rows[1]['running'] is False
                    assert not errors,errors
                    assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
                    proof.append({'system':system,'width':width,'review_before_write':True,'select_all':True,'restore':True,'automatic_retest':True,'real_jobs_changed':False})
                except Exception:
                    page.locator('#components-panel').screenshot(path=str(out/(system+'-failed.png')))
                    (out/(system+'-failure.json')).write_text(json.dumps({'calls':jobs.calls,'output':page.locator('#components-output').inner_text(),'errors':errors},indent=2),encoding='utf-8')
                    raise
                finally:page.close();server.shutdown();server.server_close();thread.join(3)
        browser.close()
    (out/'results.json').write_text(json.dumps(proof,indent=2),encoding='utf-8');print(json.dumps(proof))


if __name__=='__main__':main()
