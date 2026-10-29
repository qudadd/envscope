"""Disposable OS/network scenarios driving the production audit and remedies.

All outbound collectors are replaced; file parsing/writes run against the supplied
temporary home. This module is development-only and excluded from runtime wheels.
"""
from pathlib import Path
from unittest.mock import patch
import json
import ipaddress

from envscope.local_facts import cli_facts, config_shape
from envscope.model import make_report
from envscope.policy import Policy
from envscope.probes import audit
from envscope.state import validate_settings
from envscope.transport import Response

PROXY = 'http://127.0.0.1:7897'


def fixture_policy(settings):
    return Policy(allowed_ipv4=tuple(ipaddress.ip_network(n) for n in settings['allowed_ipv4']),
                  allowed_ipv6=tuple(ipaddress.ip_network(n) for n in settings['allowed_ipv6']))


def target(system='Windows', usage='cli', mode='direct', **overrides):
    return validate_settings({'environment_confirmed': True, 'usage': usage, 'connection_mode': mode, 'usage_country':'JP',
                              'timezone': 'China Standard Time' if system == 'Windows' else 'Asia/Shanghai',
                              'locale': 'zh-CN', 'target_proxy': PROXY if mode == 'http_proxy' else '', **overrides})


def fixture(home, settings, system='Windows', fault=None, browser=None):
    home = Path(home)
    mode = settings['connection_mode']
    bin_dir = home / 'bin'
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / 'claude').touch()
    code_file = home / '.claude/settings.json'
    code_file.parent.mkdir(parents=True, exist_ok=True)
    desktop = home / 'desktop'
    desktop.mkdir(exist_ok=True)
    desktop_file = desktop / 'claude_desktop_config.json'
    if not code_file.exists():
        code_file.write_text(json.dumps({'env': {'HTTPS_PROXY': PROXY, 'https_proxy': PROXY} if mode == 'http_proxy' else {},
                                         'mcpServers': {'fixture': {'command': 'NEVER_EXECUTE', 'env': {'SECRET': 'FIXTURE_ONLY'}}}}), encoding='utf-8')
    actual_zone = 'China Standard Time' if system == 'Windows' else 'Asia/Shanghai'
    inventory = {'platform': system, 'release': '11' if system == 'Windows' else '24.0.0', 'locale': 'zh-CN',
                 'timezone_iana': actual_zone, 'network': {'timezone_id': actual_zone,
                 'adapters': [{'Name': 'tun0', 'InterfaceDescription': 'Wintun', 'Status': 'Up', 'ifIndex': 8}] if mode == 'tun' else [],
                 'dns': ['fixture-resolver'], 'known_clients': ['mihomo'] if mode != 'direct' else [],
                 'ipv6_bindings': [{'Enabled': True}], 'ipv6_services': [{'ipv6_off': False}]},
                 'client_language': {'value': 'zh-CN', 'source': 'system-fallback'}}
    network = {'dns': [{'host': h, 'addresses': ['8.8.8.8'], 'complete': True} for h in ('claude.ai', 'api.anthropic.com')],
               'routes': [{'destination': '8.8.8.8', 'interface': 'tun0' if mode == 'tun' else 'Ethernet', 'interface_index': 8}]}
    if system == 'Darwin' and mode == 'tun':
        inventory['network']['adapters'] = [{'name':'utun5','flags':['UP','RUNNING']}]
        network['routes'] = [{'destination':'8.8.8.8','interface':'utun5','flags':'UP,GATEWAY'}]
    cli = cli_facts(home, {'PATH': str(bin_dir)})
    local = {'installed': True, 'profile_exists': True, 'desktop_config': config_shape(desktop_file), 'cli': cli,
             'account': {'valid': True, 'pending': [], 'tracked': False}, 'storage': {'free_bytes': 10 * 1024**3},
             'hosts': {'readable': True, 'overrides': []}, 'controller': {'loopback_bind': True},
             'proxy': {'environment': [], 'system': {'available': True, 'enabled': mode == 'http_proxy', 'auto_detect': False,
                       'pac_configured': False, 'endpoints': [PROXY] if mode == 'http_proxy' else [], 'bypass': {}}},
             'listeners': [{'endpoint': PROXY, 'tcp_accepts': True}] if mode == 'http_proxy' else []}
    runtime = {'status': 'pass', 'reason': 'fixture rules', 'runtime': {'tun_enabled': mode == 'tun'}}
    guard = {'registered': True, 'enabled': True, 'running': True, 'configured_mode':settings.get('client','auto')}
    if fault == 'missing_cli':
        cli['installation_count'] = 0
    elif fault == 'missing_desktop':
        local.update(installed=False, profile_exists=False)
    elif fault == 'permission':
        local['cli']['config'] = {'exists': True, 'error': 'permission_denied'}
    elif fault == 'bad_json':
        local['cli']['config'] = {'exists': True, 'valid': False, 'line': 1, 'column': 2}
    elif fault == 'tls_disabled':
        cli['tls_verification_disabled'] = True
    elif fault == 'wrong_proxy':
        cli.update(proxy_configured=True, proxy_valid=True, proxy_scheme='socks5', proxy_endpoint='socks5://127.0.0.1:7898')
    elif fault == 'provider':
        cli['vertex'] = True
    elif fault == 'system_bypass':
        local['proxy']['system']['bypass'] = {'target_matches':['claude.ai']}
    elif fault == 'system_proxy_mismatch':
        local['proxy']['system']['endpoints'] = ['http://127.0.0.1:9999']
    elif fault in ('cli_web_bypass', 'cli_api_bypass'):
        cli['proxy_bypass'] = {'target_matches':['claude.ai' if fault == 'cli_web_bypass' else 'api.anthropic.com']}
    elif fault == 'timezone':
        inventory['network']['timezone_id'] = inventory['timezone_iana'] = 'UTC'
    elif fault == 'locale':
        inventory['locale'] = 'en-US'
    elif fault == 'guard':
        guard['running'] = False
    elif fault == 'physical_route':
        network['routes'] = [{'destination':'8.8.8.8','interface':'Ethernet','interface_index':1}]
    elif fault == 'dns':
        network['dns'] = []
    elif fault == 'ipv6_disabled':
        inventory['network']['ipv6_bindings']=[{'Enabled':False}]
        inventory['network']['ipv6_services']=[{'ipv6_off':True}]
    elif fault == 'unrelated_web':
        network['dns'] = [r for r in network['dns'] if r['host'] != 'claude.ai']
        local['desktop_config'] = {'exists': True, 'valid': False}
        local.update(installed=False, profile_exists=False, account={'valid': False})

    class Transport:
        path = 'curl-explicit-proxy' if mode == 'http_proxy' else 'curl-os-routing-no-http-proxy'
        proxy = PROXY if mode == 'http_proxy' else None
        def get(self, url, family=0, headers_only=False):
            if fault=='ipv6_disabled' and family==6:
                return Response(error='curl_exit_7')
            if fault == 'timeout':
                return Response(error='deadline_exceeded')
            if fault == 'certificate':
                return Response(error='curl_exit_60', tls_verified=False)
            if 'claude.ai' in url and fault in ('web_403', 'unrelated_web'):
                return Response(status=403, tls_verified=True, clock_offset_seconds=2)
            if 'api.anthropic.com' in url and fault == 'api_405':
                return Response(status=405, tls_verified=True, clock_offset_seconds=2)
            address = '2001:4860:4860::8888' if family == 6 else '8.8.8.8'
            body = 'ip='+address+'\nloc=JP' if 'trace' in url else json.dumps({'ip': address, 'country': 'JP', 'org': 'FIXTURE'})
            return Response(status=401 if 'api.anthropic.com' in url else 200, body=body,
                            content_type='application/json', tls_verified=True, clock_offset_seconds=600 if fault == 'clock' else 2,
                            timings={'total_ms': 50})
    transport = Transport()
    with patch('envscope.probes.collect', return_value=inventory), patch('envscope.probes.bounded_facts', return_value=network), \
         patch('envscope.probes.local_snapshot', return_value=local), \
         patch('envscope.environment_info.device_information', return_value={'state':'completed','rows':[{'label':'图形','value':'Fixture GPU'}]}), \
         patch('envscope.probes.stun_observations', return_value=[{'source': 'fixture-a', 'ip': '8.8.8.8'}, {'source': 'fixture-b', 'ip': '8.8.8.8'}]), \
         patch('envscope.baseline.guard_state', return_value=guard), patch('envscope.baseline.runtime_rules', return_value=runtime):
        findings = audit(fixture_policy(settings), transport, online=True, stun=True, ipv6=True, baseline_config=settings, browser=browser)
    return findings


def report(home, settings, system='Windows', fault=None):
    return make_report(fixture(home, settings, system, fault), fixture_policy(settings), 'one-click-desktop', settings)
