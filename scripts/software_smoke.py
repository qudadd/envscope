"""Offline program-cleanup UI over loopback and disposable files only."""
import json
from pathlib import Path
import plistlib
import tempfile
import threading

from playwright.sync_api import sync_playwright,expect
from envscope.legacy_components import ComponentMigration
from envscope.legacy_software import SoftwareCleanup
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import target,fixture
from tests.test_components import ComponentsFixture


def main():
    output=Path('artifacts/software-ui');output.mkdir(parents=True,exist_ok=True);proof=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system,width in [('Windows',1024),('Windows',1280),('Darwin',1440)]:
            with tempfile.TemporaryDirectory(prefix='envscope-software-ui-') as folder:
                home=Path(folder).resolve();store=StateStore(home/'state');store.complete_learning(1)
                settings=target(system,'desktop','http_proxy',usage_country='US',country='US',target_proxy='http://127.0.0.1:7897')
                store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
                jobs=ComponentsFixture();components=ComponentMigration(store,home,io=jobs)
                software=SoftwareCleanup(home,components,system=system,processes=lambda paths:False)
                core=software.paths['core'];core.parent.mkdir(parents=True)
                core.write_text('# claude-switch SELF AUTHORED checkdetail\n')
                second=software.paths['ui' if system=='Windows' else 'app']
                if system=='Windows':second.write_text('# claude-switcher Window SELF AUTHORED\n')
                else:
                    (second/'Contents/MacOS').mkdir(parents=True)
                    (second/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.claude-switcher','CFBundleExecutable':'ClaudeSwitcher'}))
                    (second/'Contents/MacOS/ClaudeSwitcher').write_bytes(b'INERT FIXTURE ONLY')
                unknown=software.paths['guard'];unknown.write_text('FOREIGN FILE PRESERVE\n')
                account=home/'.claude-switcher/accounts/A/opaque.private.bin';account.parent.mkdir(parents=True,exist_ok=True);account.write_bytes(b'ACCOUNT_FIXTURE_ONLY')
                audits=[]
                def auditor(*a,**kwargs):
                    audits.append(True);return fixture(home,store.settings(),system,browser=kwargs.get('browser'))
                ops=Operations(store,home,components=components,software=software,discoverer=lambda:[],environment_reader=lambda:{'platform':system})
                server=make_server(store=store,operations=ops,auditor=auditor)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                page=browser.new_page(viewport={'width':width,'height':1000});errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.add_init_script('window.RTCPeerConnection=undefined');page.route('https://**/*',lambda route:route.abort())
                def idle():expect(page.locator('#start')).to_be_enabled(timeout=30000)
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('.tab[data-page=upkeep]').click()
                    expect(page.locator('#software-state')).to_have_text('尚未清理',timeout=30000);idle()
                    expect(page.locator('#software-all')).to_be_checked()
                    expect(page.locator('#software-status')).to_have_class('note manual-guidance')
                    page.locator('#software-panel summary').click()
                    expect(page.locator('[data-software=guard]')).to_be_disabled()
                    page.locator('#software-all').uncheck();expect(page.locator('#software-prepare')).to_be_disabled()
                    page.locator('[data-software=core]').check();page.locator('#software-prepare').click()
                    expect(page.locator('#software-plan')).to_contain_text('账号卷');idle()
                    self_selected=page.locator('[data-software=core]');self_selected.uncheck()
                    expect(page.locator('#software-plan')).to_be_empty();assert core.exists() and not jobs.calls
                    page.locator('#software-all').check();page.locator('#software-prepare').click();idle()
                    expect(page.locator('#software-plan')).to_contain_text('存档')
                    core.write_text('# claude-switch checkdetail CHANGED AFTER PREVIEW\n')
                    page.locator('#software-plan button').click()
                    expect(page.locator('#legacy-software-output')).to_contain_text('已改变',timeout=30000);idle()
                    assert core.exists() and not jobs.calls
                    page.locator('#software-read').click();idle()
                    page.locator('#software-all').check();page.locator('#software-prepare').click();idle()
                    page.locator('#software-plan button').click()
                    expect(page.locator('#software-state')).to_contain_text('所选程序已清理',timeout=30000);idle()
                    assert not core.exists() and not second.exists() and unknown.exists() and account.read_bytes()==b'ACCOUNT_FIXTURE_ONLY'
                    assert jobs.calls[0][0]=='retire' and audits
                    ops.software=SoftwareCleanup(home,components,system=system,processes=lambda paths:False)
                    page.locator('#software-read').click();idle();page.locator('#software-restore').click()
                    expect(page.locator('#software-plan')).to_contain_text('后台任务保持停用');idle()
                    page.locator('#software-plan button').click()
                    expect(page.locator('#software-state')).to_have_text('旧程序已恢复',timeout=30000);idle()
                    assert core.exists() and second.exists() and unknown.exists() and len(jobs.calls)==1
                    assert not errors and page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    page.locator('#software-panel').screenshot(path=str(output/(system+'-'+str(width)+'.png')))
                    proof.append({'system':system,'width':width,'selection_all_and_cancel':True,'stale_plan_refused':True,
                                  'unknown_preserved':True,'restart_restore':True,'automatic_retest':True,'real_jobs_changed':False,'real_accounts_used':False})
                finally:page.close();server.shutdown();server.server_close();thread.join(3)
        browser.close()
    (output/'results.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))


if __name__=='__main__':main()
