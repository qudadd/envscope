"""Offline language UI and interrupted recovery; no real preference writes."""
import json
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import expect,sync_playwright

from envscope.language_repair import LanguageIO,LanguageRepair
from envscope.model import Status
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture,target
from tests.test_language_repair import LanguageFixtureIO,present,ABSENT,Interrupted


def main():
    output=Path('artifacts/language-ui');output.mkdir(parents=True,exist_ok=True);results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system,width in (('Windows',1024),('Darwin',1280),('Darwin',1440)):
            with tempfile.TemporaryDirectory() as folder:
                home=Path(folder).resolve();store=StateStore(home/'state');store.complete_learning(1)
                values=target(system,'desktop','direct',usage_country='US',language='ja-JP')
                store.save_settings({k:v for k,v in values.items() if k!='environment_confirmed'},confirm_environment=True)
                io=LanguageFixtureIO() if system=='Darwin' else LanguageIO(available=False)
                manager=LanguageRepair(store,io)
                ops=Operations(store,home,discoverer=lambda:[],language_repair=manager,
                    environment_reader=lambda:{'platform':system},region_lookup=lambda _: {'state':'unavailable','reason':'离线夹具'})
                audits=[]
                def audit(*args,**kwargs):
                    rows=fixture(home,store.settings(),system,browser=kwargs.get('browser'));audits.append(True)
                    if system=='Darwin':
                        prefs=io.snapshot();actual=prefs['effective']['value'][0] if prefs['effective']['value'] else None
                        for row in rows:
                            if row.id=='baseline.language':
                                row.status=Status.PASS if actual==store.settings()['language'] and any(prefs[h]['present'] for h in ('any','current')) else Status.UNKNOWN
                                row.summary='隔离场景：应用专用语言已符合目标' if row.status==Status.PASS else '隔离场景：尚未设定应用专用语言'
                                row.evidence=[{'actual':actual,'expected':store.settings()['language']}]
                    return rows
                server=make_server(store=store,operations=ops,auditor=audit)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context=browser.new_context(viewport={'width':width,'height':1000},locale='zh-CN')
                page=context.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                page.add_init_script('window.RTCPeerConnection=undefined;');page.route('https://**/*',lambda request:request.abort())
                def idle():expect(page.locator('#start')).to_be_enabled(timeout=30000)
                def upkeep():idle();page.locator('.tab[data-page=upkeep]').click()
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('#start').click();idle()
                    if system=='Windows':
                        page.locator('.tab[data-page=checks]').click()
                        row=page.locator('[data-inspection="baseline.language"]');row.locator(':scope > summary').click()
                        expect(row).to_have_attribute('data-manual','true');expect(row).to_contain_text('Windows 尚未提供')
                        upkeep();expect(page.locator('#language-prepare')).to_be_disabled()
                        expect(page.locator('#language-target')).to_have_class('note manual-guidance')
                        page.locator('#language-panel').screenshot(path=str(output/f'{width}-manual.png'))
                    else:
                        expect(page.locator('#solution-plan')).to_contain_text('AppleLanguages');assert not io.backend().writes
                        expect(page.locator('#solution-plan')).to_contain_text('ja-JP')
                        page.locator('#apply-solution').click();idle();assert len(audits)>=2
                        assert next(f for f in server.last_raw_report['findings'] if f['id']=='baseline.language')['status']=='pass'
                        upkeep();expect(page.locator('#language-state')).to_have_text('上次应用偏好已读回')
                        page.locator('#language-restore').click();expect(page.locator('#language-plan')).to_contain_text('原来不存在的键删除')
                        page.locator('#language-plan button').click();idle();assert io.backend().values['any']==ABSENT
                        expect(page.locator('#language-state')).to_have_text('原应用语言键已恢复')
                        io.backend().values['current']=present('fr-FR','en-US');before=io.snapshot()
                        page.locator('#language-prepare').click()
                        expect(page.locator('#language-plan')).to_contain_text('ByHost')
                        page.locator('#language-panel').screenshot(path=str(output/f'{width}-preview.png'))
                        page.locator('#language-plan button').click();idle();assert io.backend().values['current']==present('ja-JP')
                        page.locator('#language-restore').click();page.locator('#language-plan button').click();idle();assert io.snapshot()==before
                        io.backend().fail=True
                        page.locator('#language-prepare').click();page.locator('#language-plan button').click();idle()
                        expect(page.locator('#language-output')).to_have_class('solution-output manual-guidance');assert io.snapshot()==before
                        # Simulate service loss after the first real fixture write;
                        # construct a new coordinator over the persisted journal.
                        plan=manager.prepare(server.last_raw_report);assert plan['state']=='planned';io.backend().crash=True
                        try:manager.apply(plan['plan_id'],True)
                        except Interrupted:pass
                        else:raise AssertionError('Interruption was not exercised')
                        manager=LanguageRepair(store,io);ops.language_repair=manager;ops.solutions.language=manager
                        page.locator('#upkeep-refresh').click()
                        expect(page.locator('#language-state')).to_have_text('上次操作未完成')
                        expect(page.locator('#language-prepare')).to_be_disabled();expect(page.locator('#language-restore')).to_be_enabled()
                        page.locator('#language-panel').screenshot(path=str(output/f'{width}-recovery.png'))
                        page.locator('#language-restore').click();page.locator('#language-plan button').click();idle()
                        expect(page.locator('#language-state')).to_have_text('原应用语言键已恢复');assert io.snapshot()==before
                    assert not errors,errors;assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    results.append({'platform':system,'width':width,'fixture':True,'manual_windows_guidance':system=='Windows',
                        'one_stop_language_preview':system=='Darwin','byhost_and_absence_restored':system=='Darwin',
                        'failed_write_recovery':system=='Darwin','interrupted_coordinator_restarted':system=='Darwin',
                        'real_application_preferences_changed':False,'page_errors':errors})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(timeout=3)
        browser.close()
    (output/'result.json').write_text(json.dumps(results,ensure_ascii=False,indent=2));print(json.dumps(results))


if __name__=='__main__':main()
