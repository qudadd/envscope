"""Guard setup, heartbeat, failure and removal with disposable injected adapters."""
import json
from pathlib import Path
import tempfile
import threading
from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect, sync_playwright
from envscope.operations import Operations
from envscope.process_guard import ProcessGuard
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import fixture, target
from tests.test_process_guard import GuardIOFixture, GuardSchedulerFixture


def main():
    out = Path('artifacts/process-guard-ui'); out.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        for system, mode in [('Windows','http_proxy'), ('Darwin','tun')]:
            with tempfile.TemporaryDirectory() as temp:
                home = Path(temp).resolve(); store = StateStore(home/'state')
                settings = target(system, 'desktop', mode, usage_country='US', country='US')
                store.save_settings({k:v for k,v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
                store._write('learning.private.json', {'completed':True,'version':1})
                io, scheduler = GuardIOFixture(), GuardSchedulerFixture()
                guard = ProcessGuard(store, home, io, scheduler)
                auditor = lambda *args, **kw: fixture(home, kw.get('baseline_config') or store.settings(), system)
                opened = []
                ops = Operations(store,home,process_guard=guard,discoverer=lambda:[],
                                 region_lookup=lambda _: {'state':'unavailable','reason':'fixture'},
                                 environment_reader=lambda:{'platform':system},remedy_opener=lambda v:opened.append(v) or True)
                server = make_server(store=store,operations=ops,auditor=auditor)
                thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context = browser.new_context(viewport={'width':1280,'height':950})
                page = context.new_page();errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.add_init_script('window.RTCPeerConnection=undefined;');page.route('https://**/*',lambda r:r.abort())
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('#start').click();expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    if mode=='tun':
                        page.locator('#process-guard-load').click()
                        expect(page.locator('#process-guard-interface')).to_contain_text('utun9')
                        page.locator('#process-guard-interface').select_option('utun9')
                    else:expect(page.locator('#process-guard-interface-row')).not_to_be_visible()
                    page.locator('#process-guard-prepare').click()
                    expect(page.locator('#process-guard-plan')).to_contain_text('未保存内容可能丢失')
                    assert not scheduler.calls and not io.stops
                    page.locator('#process-guard-plan button').click()
                    expect(page.locator('#process-guard-state')).to_contain_text('等待首次心跳')
                    guard.pulse();page.locator('#process-guard-refresh').click()
                    expect(page.locator('#process-guard-state')).to_have_text('正在守护')
                    io.observation['targets']=[{'pid':123,'created':1,'exe':'fixture'}]
                    io.online=False;io.observation['interfaces']=[]
                    guard.pulse();page.locator('#process-guard-refresh').click()
                    expect(page.locator('#process-guard-state')).to_contain_text('桌面未运行')
                    page.locator('#process-guard-panel details').evaluate('(node)=>node.open=true')
                    expect(page.locator('#process-guard-events')).to_contain_text('已确认 Claude 桌面进程退出')
                    page.locator('#process-guard-logs').click();expect(page.locator('#process-guard-output')).to_contain_text('已打开本机')
                    assert opened==['guard-logs'] and len(io.stops)==1
                    expect(page.locator('#process-guard-refresh')).to_be_enabled()
                    expect(page.locator('#process-guard-stop')).to_be_enabled()
                    page.locator('#process-guard-panel').screenshot(path=str(out/(system+'-stopped.png')))
                    page.locator('#process-guard-stop').click();expect(page.locator('#process-guard-state')).to_have_text('未启用')
                    guard.pulse();assert len(io.stops)==1 and not scheduler.definition and not errors
                    results.append({'system':system,'mode':mode,'review_before_enable':True,'heartbeat_required':True,'stopped_and_logged':True,'disabled':True,'real_user_processes_changed':False})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(3)
        browser.close()
    (out/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8');print(json.dumps(results))


if __name__=='__main__':main()
