"""Offline WireGuard UI: choose tunnel, diagnose, pin guard, stop and recover.

All service/process/network adapters are fixtures. No real VPN or accounts.
"""
import json
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import expect, sync_playwright
from envscope.operations import Operations
from envscope.model import Status
from envscope.process_guard import ProcessGuard
from envscope.service import make_server
from envscope.state import StateStore
from scripts.environment_fixtures import target
from tests.test_process_guard import GuardIOFixture, GuardSchedulerFixture
from tests.test_wireguard import observed, wireguard_findings, SERVICE, PREFIX


def main():
    output = Path('artifacts/wireguard-ui'); output.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        for width in (1024, 1440):
            with tempfile.TemporaryDirectory(prefix='envscope-wireguard-ui-') as temporary:
                home = Path(temporary).resolve(); store = StateStore(home/'state'); store.complete_learning(1)
                values = target('Windows', 'desktop', 'tun', usage_country='US')
                store.save_settings({k: v for k, v in values.items() if k != 'environment_confirmed'}, confirm_environment=True)
                io, scheduler = GuardIOFixture(), GuardSchedulerFixture()
                services = observed()
                second = dict(services['services'][0], service=PREFIX+'Other', tunnel='Other', interface='Other')
                services['services'].append(second)
                io.observation.update(wireguard=services, interfaces=[{'name': 'EnvScope Fixture US', 'up': True}, {'name': 'Other VPN', 'up': True}])
                guard = ProcessGuard(store, home, io, scheduler)
                route = ['EnvScope Fixture US']
                def inventory(): return {'platform': 'Windows', 'network': {'wireguard': services}}
                ops = Operations(store, home, process_guard=guard, discoverer=lambda: [], environment_reader=inventory,
                    region_lookup=lambda _: {'state': 'unavailable', 'reason': '离线测试，不定位'}, remedy_opener=lambda _: False)
                def auditor(*args, **kw):
                    rows = wireguard_findings(home, store.settings(), services, route=route[0])
                    for row in rows:
                        if row.id == 'baseline.guard':
                            state = guard.status()
                            row.status = Status.PASS if state.get('running') else Status.WARN
                            row.evidence = [{'kind': 'envscope-process-guard', 'configured_mode': 'wireguard',
                                             'registered': state.get('scheduler', {}).get('registered', False),
                                             'enabled': state.get('enabled', False), 'running': state.get('running', False)}]
                    return rows
                server = make_server(store=store, operations=ops, auditor=auditor)
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                context = browser.new_context(viewport={'width': width, 'height': 1000}, locale='zh-CN')
                page = context.new_page(); errors = []; page.on('pageerror', lambda e: errors.append(str(e)))
                page.add_init_script('window.RTCPeerConnection=undefined;'); page.route('https://**/*', lambda r: r.abort())
                def idle(): expect(page.locator('#start')).to_be_enabled(timeout=30000)
                def all_checks():
                    idle(); page.locator('.tab[data-page=checks]').click()
                    return page.locator('[data-inspection="target.wireguard"]')
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port), wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible(): page.locator('#learning-skip').click()
                    page.locator('#target-edit').click()
                    expect(page.locator('#target-observed')).to_contain_text('Windows')
                    expect(page.locator('#target-confirm')).to_be_enabled(timeout=15000)
                    page.locator('#target-form select[name=client]').select_option('wireguard')
                    expect(page.locator('#target-wireguard')).to_be_visible()
                    expect(page.locator('#target-form select[name=connection_mode]')).to_have_value('tun')
                    expect(page.locator('#target-wireguard-note')).to_contain_text('请选择本次')
                    page.locator('#target-form select[name=wireguard_service]').select_option(SERVICE)
                    page.locator('#target-wireguard-read').click()
                    expect(page.locator('#target-wireguard-read')).to_be_enabled()
                    expect(page.locator('#target-form select[name=wireguard_service]')).to_have_value(SERVICE)
                    page.locator('#target-wireguard').screenshot(path=str(output/f'{width}-target.png'))
                    page.locator('#target-confirm').click(); idle()
                    expect(all_checks()).to_contain_text('所选 WireGuard 隧道服务及所属进程已核对')
                    assert store.settings()['wireguard_service'] == SERVICE
                    assert not scheduler.calls and not io.stops
                    # Manual controls also select the single matching NIC, never
                    # offer another active VPN as a substitute for this service.
                    page.locator('.tab[data-page=upkeep]').click()
                    page.locator('#process-guard-load').click()
                    expect(page.locator('#process-guard-interface')).to_have_value('EnvScope Fixture US')
                    expect(page.locator('#process-guard-interface')).not_to_contain_text('Other VPN')
                    page.locator('#process-guard-prepare').click()
                    expect(page.locator('#process-guard-plan')).to_contain_text(SERVICE)
                    expect(page.locator('#process-guard-plan')).to_contain_text('固定 WireGuard 程序摘要')
                    assert not scheduler.calls
                    page.locator('#process-guard-plan button').click()
                    expect(page.locator('#process-guard-state')).to_contain_text('等待首次心跳')
                    guard.pulse(); page.locator('#process-guard-refresh').click()
                    expect(page.locator('#process-guard-state')).to_have_text('正在守护')
                    services['services'][0].update(state='stopped', verified=False)
                    io.observation['targets'] = [{'pid': 123, 'created': 1, 'exe': 'fixture'}]
                    guard.pulse(); page.locator('#process-guard-refresh').click()
                    expect(page.locator('#process-guard-status')).to_contain_text('所选 WireGuard 隧道服务离线')
                    assert len(io.stops) == 1
                    page.locator('.tab[data-page=audit]').click(); page.locator('#start').click()
                    expect(all_checks()).to_contain_text('所选 WireGuard 隧道服务未运行')
                    page.locator('[data-inspection="target.wireguard"]').screenshot(path=str(output/f'{width}-offline.png'))
                    services['services'][0].update(observed()['services'][0]); route[0] = 'Other VPN'
                    page.locator('.tab[data-page=audit]').click(); page.locator('#start').click(); all_checks()
                    expect(page.locator('[data-inspection="target.tun_route"]')).to_contain_text('目标地址存在非隧道选路')
                    services['services'][0]['error'] = 'permission_denied'
                    page.locator('.tab[data-page=audit]').click(); page.locator('#start').click()
                    expect(all_checks()).to_contain_text('系统拒绝读取所选 WireGuard 服务或进程')
                    page.locator('.tab[data-page=upkeep]').click(); page.locator('#process-guard-stop').click()
                    expect(page.locator('#process-guard-state')).to_have_text('未启用')
                    assert not scheduler.definition and not errors
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    results.append({'width': width, 'explicit_tunnel': True, 'exact_nic': True, 'review_before_guard': True,
                                    'offline_error_and_stop': True, 'other_vpn_rejected': True, 'permission_explicit': True,
                                    'removed': True, 'real_services_changed': False, 'errors': errors})
                finally:
                    context.close(); server.shutdown(); server.server_close(); thread.join(3)
        browser.close()
    (output/'result.json').write_text(json.dumps(results, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__': main()
