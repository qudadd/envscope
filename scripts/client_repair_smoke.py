"""Offline Windows/macOS UI walkthrough with dummy files and fake OS adapters."""
import json
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import expect,sync_playwright
from envscope.client_repair import ClientRepair
from envscope.client_config import tun_model
from envscope.operations import Operations
from envscope.process_guard import ProcessGuard
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import target
from tests.test_client_repair import ClientFixture
from tests.test_client_workflow import client_findings
from tests.test_process_guard import GuardIOFixture,GuardSchedulerFixture


def main():
    output=Path('artifacts/client-repair-ui');output.mkdir(parents=True,exist_ok=True)
    evidence=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system,width in (('Windows',1024),('Darwin',1280),('Windows',1440)):
            with tempfile.TemporaryDirectory() as folder:
                home=Path(folder).resolve();store=StateStore(home/'state');store.complete_learning(1)
                values=target(system,'desktop','tun',usage_country='US',client='clash-verge',protection='guarded',
                              ipv6_mode='allowlist',allowed_ipv6=['2001:4860::/32'])
                store.save_settings({k:v for k,v in values.items() if k!='environment_confirmed'},confirm_environment=True)
                io=ClientFixture(home,system);seconds=[0]
                def sleep(n):seconds[0]+=n
                client=ClientRepair(store,io,clock=lambda:seconds[0],sleeper=sleep)
                guard_io,scheduler=GuardIOFixture(),GuardSchedulerFixture()
                guard_io.observation['interfaces']=[{'name':'tun0' if system=='Windows' else 'utun5','up':True}]
                guard=ProcessGuard(store,home,guard_io,scheduler)
                ops=Operations(store,home,discoverer=lambda:[],client_repair=client,process_guard=guard,
                    environment_reader=lambda:{'platform':system},region_lookup=lambda _: {'state':'unavailable','reason':'离线夹具'})
                client.transaction_lock=lambda:ops.accounts._lock()
                audits=[]
                def audit(*args,**kwargs):
                    audits.append(True);return client_findings(home,store,io,guard,system,kwargs.get('browser'))
                server=make_server(store=store,operations=ops,auditor=audit)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context=browser.new_context(viewport={'width':width,'height':1000},locale='zh-CN')
                page=context.new_page();errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*',lambda request:request.abort())
                def idle():expect(page.locator('#start')).to_be_enabled(timeout=30000)
                def upkeep():idle();page.locator('.tab[data-page=upkeep]').click()
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible():page.locator('#learning-skip').click()
                    page.locator('#start').click()
                    expect(page.locator('#solution-plan')).to_contain_text('enable_tun_mode',timeout=15000)
                    assert not io.calls and not scheduler.calls
                    page.locator('#apply-solution').click()
                    # A new review uses the tunnel observed after client repair.
                    expect(page.locator('#solution-plan')).to_contain_text('监测网卡：',timeout=20000)
                    assert len(audits)>=2 and not scheduler.calls
                    page.locator('#solution-tools').screenshot(path=str(output/f'{width}-next-review.png'))
                    page.locator('#apply-solution').click();idle()
                    assert scheduler.calls and guard.status()['state']=='waiting'
                    guard.pulse();assert guard.status()['state']=='armed'
                    upkeep();page.locator('#client-load').click()
                    expect(page.locator('#client-app')).to_have_value('fixture-proxy')
                    expect(page.locator('#client-tun')).to_be_checked()
                    page.locator('#client-restore').click()
                    expect(page.locator('#client-plan')).to_contain_text('保留其他字段')
                    page.locator('#client-plan button').click();idle()
                    expect(page.locator('#client-state')).to_have_text('已恢复原偏好与启动状态',timeout=10000)
                    assert not tun_model(io.preference.read_bytes())['value']
                    io.decline=True
                    page.locator('#client-prepare').click()
                    expect(page.locator('#client-plan')).to_contain_text('不会强制退出 Claude',timeout=1000) if page.locator('#client-force').is_checked() else None
                    assert not tun_model(io.preference.read_bytes())['value']
                    page.locator('#client-plan').screenshot(path=str(output/f'{width}-preview.png'))
                    page.locator('#client-tun').uncheck();expect(page.locator('#client-plan')).to_be_empty()
                    page.locator('#client-tun').check();page.locator('#client-prepare').click()
                    page.locator('#client-plan button').click();idle()
                    expect(page.locator('#client-output')).to_contain_text('所选代理客户端未退出')
                    assert not tun_model(io.preference.read_bytes())['value']
                    details=page.locator('#client-panel details');details.locator('summary').click()
                    page.locator('#client-force').check();page.locator('#client-prepare').click()
                    expect(page.locator('#client-plan')).to_contain_text('不会强制退出 Claude')
                    page.locator('#client-plan button').click();idle()
                    expect(page.locator('#client-state')).to_have_text('上次操作已读回',timeout=15000)
                    assert tun_model(io.preference.read_bytes())['value'];expect(page.locator('#client-force')).not_to_be_checked()
                    io.decline=False
                    page.locator('#client-restore').click();page.locator('#client-plan button').click();idle()
                    io.bad=True
                    page.locator('#client-prepare').click();page.locator('#client-plan button').click();idle()
                    expect(page.locator('#client-state')).to_have_text('已恢复原偏好与启动状态',timeout=15000)
                    expect(page.locator('#client-output')).to_have_class('solution-output manual-guidance')
                    assert not tun_model(io.preference.read_bytes())['value']
                    page.locator('#client-panel').screenshot(path=str(output/f'{width}-rollback.png'))
                    assert not errors,errors
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    evidence.append({'system':system,'width':width,'fixture':True,'one_stop_staged_recheck':True,
                        'native_guard_uses_observed_tunnel':True,'normal_exit_declined_preserves_preferences':True,
                        'separately_reviewed_force':True,'independent_retest':True,'failed_verification_restores_original':True,
                        'actual_installed_app_changes':0,'page_errors':errors})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(timeout=3)
        browser.close()
    (output/'result.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
    print(json.dumps(evidence))


if __name__=='__main__':main()
