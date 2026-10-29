"""A user's desired environment, separate from observed facts and privacy proof."""
import hashlib
import json
import re

DEFAULTS = {"environment_confirmed": False, "connection_mode": "inherit", "provider": "anthropic",
            "auth_mode": "existing", "language": "", "ipv6_mode": "observe", "protection": "standard", "target_proxy": "", "usage_country": "", "region_profile": "", "wireguard_service": ""}
FIELDS = set(DEFAULTS) | {"usage", "country", "timezone", "locale", "client", "proxy_group", "webrtc_policy", "allowed_ipv4", "allowed_ipv6", "require_guard", "require_rules"}
USAGES = {"desktop": "Claude 桌面版", "cli": "Claude Code", "both": "桌面版与 Code", "web": "Claude 网页"}
CONNECTIONS = {"direct": "直连", "http_proxy": "HTTP / 系统代理", "tun": "TUN / VPN"}
PROVIDERS = {"anthropic": "Anthropic 官方", "custom": "自定义接口", "bedrock": "Amazon Bedrock", "vertex": "Google Vertex", "foundry": "Microsoft Foundry"}


def validate(values):
    from .wireguard import valid_service
    if not valid_service(values['wireguard_service'], empty=True):
        raise ValueError('WireGuard 隧道服务名称无效，请从读取结果选择')
    from .region_profiles import validate_profile
    validate_profile(values)
    if not isinstance(values['usage_country'], str) or values['usage_country'] and not re.fullmatch('[A-Za-z]{2}', values['usage_country']):
        raise ValueError('实际使用地区请填写两个字母的国家 / 地区代码，例如 CN、RU、US')
    values['usage_country'] = values['usage_country'].upper()
    if type(values['environment_confirmed']) is not bool:
        raise ValueError('目标确认状态无效')
    choices = {'connection_mode': {'inherit', *CONNECTIONS}, 'provider': set(PROVIDERS),
               'auth_mode': {'existing', 'subscription', 'api_key', 'managed'},
               'ipv6_mode': {'observe', 'disabled', 'allowlist'}, 'protection': {'standard', 'guarded'}}
    for key, allowed in choices.items():
        if not isinstance(values[key], str) or values[key] not in allowed:
            raise ValueError('目标选项无效：' + key)
    if not isinstance(values['language'], str) or values['language'] and not re.fullmatch(r'[a-zA-Z]{2,3}(?:[-_][a-zA-Z0-9]{2,8})*', values['language']):
        raise ValueError('语言请使用 zh-CN、en-US 等代码')
    if not isinstance(values['target_proxy'], str):
        raise ValueError('代理目标无效')
    if values['target_proxy']:
        from .remedies import safe_local_proxy
        if not safe_local_proxy(values['target_proxy']) or not values['target_proxy'].startswith(('http://', 'https://')):
            raise ValueError('可自动配置的连接仅支持不含凭据的本机 HTTP / HTTPS 地址')
    if values['environment_confirmed']:
        if values['usage'] not in USAGES or values['connection_mode'] not in CONNECTIONS:
            raise ValueError('请明确选择使用方式和连接方式')
        if values['target_proxy'] and values['connection_mode'] != 'http_proxy':
            raise ValueError('本机 HTTP 地址仅适用于 HTTP / 系统代理方式')
        if values.get('client') == 'wireguard' and values['connection_mode'] != 'tun':
            raise ValueError('WireGuard 请使用 TUN / VPN 连接方式')
        if values['wireguard_service'] and values.get('client') != 'wireguard':
            raise ValueError('具体隧道服务仅用于 WireGuard 模式')
        if values['ipv6_mode'] == 'allowlist' and not values['allowed_ipv6']:
            raise ValueError('验证 IPv6 允许范围前，请填写允许的网段')
        if values['protection'] == 'guarded' and values['connection_mode'] != 'tun':
            raise ValueError('严格保护需要明确选择 TUN / VPN；普通连接可使用标准检查')
        if values['protection'] == 'guarded' and values['ipv6_mode'] == 'observe':
            raise ValueError('严格保护请明确选择 IPv6 已关闭或指定允许网段，不能只观察')
        if values['usage'] in ('web', 'desktop') and (values['provider'] != 'anthropic' or values['auth_mode'] in ('api_key', 'managed')):
            raise ValueError('此处的接口及 API 认证目标用于 Claude Code')
        if values['language'] and values['usage'] in ('web', 'cli'):
            raise ValueError('本机语言读取仅覆盖 Claude 桌面偏好；网页版或 Code 请在实际会话中确认语言')


def fingerprint(settings):
    # Adding an unused tunnel selector must not invalidate older, unrelated
    # approved non-WireGuard policies. Any actual service selection is included.
    fields = FIELDS - ({'wireguard_service'} if settings.get('client') != 'wireguard' and not settings.get('wireguard_service') else set())
    return hashlib.sha256(json.dumps({k: settings.get(k) for k in sorted(fields)}, sort_keys=True).encode()).hexdigest()


def summary(settings):
    if not settings.get('environment_confirmed'):
        return {'confirmed': False, 'summary': '首次检测前，确认使用方式与连接方式。', 'fingerprint': fingerprint(settings)}
    labels = [USAGES[settings['usage']], CONNECTIONS[settings['connection_mode']]]
    if settings.get('timezone'):
        labels.append(settings['timezone'])
    return {'confirmed': True, 'summary': '，'.join(labels), 'fingerprint': fingerprint(settings),
            'connection_mode': settings['connection_mode'], 'provider': settings['provider'],
            'protection': settings['protection'], 'ipv6_mode': settings['ipv6_mode']}


def suggest(settings, inventory, cli, proxies):
    """Suggestions are not confirmation, and never become measurement evidence."""
    network = inventory.get('network', {})
    actual = {'system': inventory.get('platform', 'unknown'), 'version': inventory.get('release', ''),
              'timezone': network.get('timezone_id') or inventory.get('timezone_iana') or '',
              'locale': inventory.get('locale') or '', 'language': inventory.get('client_language', {}).get('value') or ''}
    proposed = {k: settings.get(k) for k in FIELDS if k != 'environment_confirmed'}
    if proposed['usage'] == 'auto':
        proposed['usage'] = 'cli' if cli.get('installation_count', 0) else 'desktop'
    if proposed['connection_mode'] == 'inherit':
        adapters = network.get('adapters', [])
        tun = any(re.search(r'TUN|TAP|utun|WireGuard|VPN', str(a.get('InterfaceDescription', a.get('name', ''))), re.I) for a in adapters)
        proposed['connection_mode'] = 'http_proxy' if proxies else 'tun' if tun else 'direct'
    # Observed values are shown above the form, never silently made into goals.
    from .region_profiles import profiles
    return {'state': 'completed', 'observed': actual, 'proposed': proposed,
            'profiles': profiles(actual['system']),
            'proxies': [{'url': p['url']} for p in proxies if isinstance(p.get('url'), str)],
            'wireguard': network.get('wireguard', {'platform': actual['system'], 'complete': False, 'services': [], 'error': 'unavailable'}),
            'note': '这是只读建议。确认仅保存检测目标，不会修改系统时区、语言、网络或账号。'}


def selected_hosts(settings):
    hosts = []
    if settings.get('usage') in ('desktop', 'web', 'both'):
        hosts.append('claude.ai')
    if settings.get('usage') in ('cli', 'both') and settings.get('provider', 'anthropic') == 'anthropic':
        hosts.append('api.anthropic.com')
    return hosts


def plan(settings):
    if not settings.get('environment_confirmed'):
        return None
    usage, mode = settings['usage'], settings['connection_mode']
    required = {'target.region', 'target.dns', 'target.tls', 'target.service', 'target.path', 'target.clock', 'http.egress'}
    excluded = {k: '本项为全部端点的合并记录；所选用途在目标检查中单独判断。' for k in ('extra.dns_resolution', 'extra.tls', 'extra.clock', 'baseline.reachability')}
    references = {'baseline.asn', 'baseline.ip_stability', 'system.inventory', 'extra.timing', 'extra.hosts', 'baseline.dns'}
    cli_used, desktop_used = usage in ('cli', 'both'), usage in ('desktop', 'both')
    if cli_used:
        required.update(('extra.cli_paths', 'extra.cli_env', 'target.provider', 'target.cli_path', 'extra.storage', 'target.config'))
        if settings['auth_mode'] in ('api_key', 'subscription', 'managed'):
            required.add('target.auth')
    else:
        excluded.update({k: '所选用途不需要本机 Claude Code。' for k in ('extra.cli_paths', 'extra.cli_env')})
    if desktop_used:
        required.update(('extra.desktop', 'extra.profile', 'extra.account', 'extra.storage', 'target.config'))
    else:
        excluded.update({k: '所选用途不需要 Claude 桌面资料。' for k in ('extra.desktop', 'extra.profile', 'extra.account')})
    excluded['extra.config'] = '原始记录包含桌面和 Code 配置；所选配置在目标配置检查中判断。'
    if usage == 'web':
        excluded['extra.storage'] = '网页版不依赖所检查的本机 Claude 资料目录。'
    if mode != 'tun':
        excluded.update({k: '所选连接方式不要求 TUN、内核控制接口或进程守护。' for k in ('baseline.tun', 'extra.runtime_tun', 'extra.controller_bind', 'extra.target_route', 'baseline.rules', 'baseline.guard')})
    else:
        required.update(('baseline.tun', 'target.tun_route'))
        references.update(('extra.runtime_tun', 'extra.controller_bind', 'extra.target_route', 'baseline.rules', 'baseline.guard'))
    if settings.get('client') == 'wireguard' and mode == 'tun':
        required.add('target.wireguard')
        # WireGuard is not a Clash controller and has no rule injection API.
        excluded.update({k: 'WireGuard 不提供 Clash 控制器或规则脚本；此项不适用。' for k in
                         ('extra.runtime_tun', 'extra.controller_bind', 'baseline.rules')})
    if mode != 'http_proxy':
        excluded.update({k: '所选方式通过系统路由连接，不要求 HTTP 代理客户端或监听端口。' for k in ('baseline.proxy', 'extra.proxy_layers', 'extra.proxy_listener', 'extra.proxy_bypass')})
    else:
        references.update(('baseline.proxy', 'extra.proxy_layers', 'extra.proxy_listener', 'extra.proxy_bypass'))
    if settings['protection'] == 'guarded':
        required.update(('baseline.proxy', 'baseline.tun', 'baseline.ipv6', 'udp.stun'))
        if settings.get('require_guard', True):
            required.add('baseline.guard')
        if settings.get('require_rules', True) and settings.get('client') != 'wireguard':
            required.add('baseline.rules')
        for key in required:
            excluded.pop(key, None)
    else:
        references.update(('udp.stun', 'browser.webrtc', 'baseline.webrtc'))
    if settings['ipv6_mode'] != 'observe':
        required.add('target.ipv6')
    else:
        references.update(('baseline.ipv6', 'http.ipv6', 'browser.http_v6'))
    if usage == 'cli':
        excluded.update({k: 'Code 的本机连接不使用当前窗口的浏览器实时通信；原始记录保留。' for k in ('browser.webrtc', 'browser.http_v4', 'browser.http_v6', 'baseline.webrtc')})
    for key, target in (('country', 'country'), ('timezone', 'timezone'), ('locale', 'locale'), ('language', 'language')):
        if settings.get(target):
            required.add('baseline.'+key)
        else:
            references.add('baseline.'+key)
    return {'required': sorted(required), 'excluded': excluded, 'references': sorted(references-required)}


def scoped_preferences(settings):
    if not settings.get('environment_confirmed') or settings['protection'] == 'guarded':
        return settings
    return {**settings, 'require_guard': False, 'require_rules': False}


def build_findings(findings, settings):
    """Derive scoped checks from native evidence, never from the desired values."""
    if not settings.get('environment_confirmed'):
        return []
    from urllib.parse import urlsplit
    import ipaddress
    from .model import Finding

    raw = {f.id: f.to_dict() for f in findings}
    def evidence(key):
        return [v for v in raw.get(key, {}).get('evidence', []) if isinstance(v, dict)]
    def first(key):
        return next(iter(evidence(key)), {})
    results = []
    def add(key, title, status, message, data, fix, limits=()):
        results.append(Finding('target.'+key, title, status, message, 'confirmed-target-environment', data, list(limits), fix))
    usage, mode = settings['usage'], settings['connection_mode']
    hosts = selected_hosts(settings)
    custom = usage in ('cli', 'both') and settings['provider'] != 'anthropic'
    responses = {urlsplit(r.get('endpoint', '')).hostname: r for r in evidence('baseline.reachability')}
    selected = [responses[h] for h in hosts if h in responses]
    complete = bool(hosts) and len(selected) == len(hosts) and not custom
    dns = {r.get('host'): r for r in evidence('extra.dns_resolution')}
    dns_rows = [dns[h] for h in hosts if h in dns]
    dns_ok = bool(hosts) and len(dns_rows) == len(hosts) and not custom
    suspicious = False
    for row in dns_rows:
        try:
            addresses = [ipaddress.ip_address(v) for v in row.get('addresses', [])]
            dns_ok = dns_ok and row.get('complete') is True and bool(addresses)
            suspicious |= any((v.is_private or v.is_loopback or v.is_link_local) and not (v.version == 4 and v in ipaddress.ip_network('198.18.0.0/15')) for v in addresses)
        except (ValueError, TypeError):
            dns_ok = False
    provider_note = '自定义或云提供方的实际端点未做认证探测，请在该提供方完成连接验证。'
    add('dns', '所选用途的域名解析', 'fail' if any(r.get('error') for r in dns_rows) else 'warn' if suspicious else 'pass' if dns_ok else 'unknown',
        '所选目标已解析' if dns_ok and not suspicious else provider_note if custom else '所选目标解析缺失或需要复核', dns_rows,
        '检查目标域名、系统 DNS 与 hosts 后复检；代理的远端解析不等于系统解析。')
    tls_bad = any(r.get('tls_verified') is False for r in selected)
    tls_ok = complete and all(r.get('tls_verified') is True and not r.get('error') for r in selected)
    add('tls', '所选用途的证书校验', 'fail' if tls_bad else 'pass' if tls_ok else 'unknown',
        '所选端点的 TLS 证书校验通过' if tls_ok else '所选端点证书校验失败' if tls_bad else provider_note if custom else '所选端点证书证据不完整', selected,
        '核对自动校时与可信 CA，保留证书验证；企业证书由组织提供。')
    service_ok = complete and all(type(r.get('http_status')) is int and (200 <= r['http_status'] < 400 or r['http_status'] == 401)
                                  and not r.get('error') and r.get('tls_verified') is True for r in selected)
    service_bad = any(r.get('error') or r.get('http_status') in (407, 429) or isinstance(r.get('http_status'), int) and r['http_status'] >= 500 for r in selected)
    codes = '、'.join(str(r['http_status']) for r in selected if r.get('http_status'))
    add('service', '所选用途的服务连接', 'pass' if service_ok else 'fail' if service_bad else 'warn' if codes else 'unknown',
        '无认证连接已回应，账号权限需实际登录确认' if service_ok else provider_note if custom else '目标连接本次失败；查看返回的错误并处理' if service_bad else '目标返回 HTTP '+codes+'，需要确认访问条件' if codes else '目标连接未完成或访问校验仍待处理', selected,
        '403 请在实际 Claude 窗口完成访问校验；405 不是服务正常证据；超时检查所选连接，429 稍后重试。',
        ['此处验证连接，不验证订阅、密钥有效性或真实回复。'])
    path_rows = evidence('http.egress')
    path_ok = bool(path_rows) and all(not r.get('error') and r.get('ip') for r in path_rows)
    expected_path = 'curl-os-routing-no-http-proxy' if mode in ('direct', 'tun') else 'curl-explicit-proxy'
    path_ok = path_ok and all(r.get('path') == expected_path for r in path_rows)
    system = first('extra.proxy_layers').get('system', {})
    # Desktop/browser routing is not controlled by the probe's curl options.
    desktop_path = usage in ('desktop', 'both', 'web')
    system_known = system.get('available') is True and not system.get('pac_configured') and system.get('auto_detect') is False
    route_mismatch = False
    if desktop_path:
        if mode == 'http_proxy':
            expected_proxy = settings.get('target_proxy') or next((r.get('proxy_endpoint') for r in path_rows if r.get('proxy_endpoint')), '')
            endpoints = {p.rstrip('/') for p in system.get('endpoints', [])}
            bypass = system.get('bypass', {})
            bypassed = bypass.get('all_hosts') or bool(set(hosts) & set(bypass.get('target_matches', [])))
            system_ok = system_known and system.get('enabled') is True and bool(system.get('endpoints'))
            system_ok = system_ok and bool(expected_proxy) and endpoints == {expected_proxy.rstrip('/')} and not bypassed
            route_mismatch = system_known and not system_ok
            path_ok = path_ok and system_ok
        else:
            route_mismatch = system_known and system.get('enabled') is True
            path_ok = path_ok and system_known and system.get('enabled') is False
    add('path', '连接方式与目标一致', 'fail' if route_mismatch else 'pass' if path_ok else 'unknown',
        '探测路径及所检查的应用代理配置符合目标' if path_ok else '系统代理与所选连接方式不一致' if route_mismatch else '尚未核实所选连接路径',
        [{'expected': CONNECTIONS[mode], 'probe_paths': sorted({r.get('path', '') for r in path_rows}), 'system_proxy': system}],
        '在系统代理设置中按目标连接方式调整后复检。TUN 另查隧道状态；PAC、浏览器扩展及进程流量需在实际应用确认。',
        ['探测路径和配置一致不证明 Claude 进程全流量经过同一路径。'])
    if mode == 'tun':
        network = first('system.inventory').get('network', {})
        adapters = network.get('adapters', [])
        wg_state, wg_row = None, None
        if settings.get('client') == 'wireguard':
            from .wireguard import select_service, finding as wireguard_finding
            observed = network.get('wireguard', {})
            results.append(wireguard_finding(observed, settings.get('wireguard_service', '')))
            wg_state, wg_row = select_service(observed, settings.get('wireguard_service', ''))
        tunnels = [a for a in adapters if (a.get('Status') == 'Up' or 'UP' in a.get('flags', [])) and
                   re.search(r'TUN|TAP|Wintun|WireGuard|VPN|Tailscale|utun', str(a.get('InterfaceDescription', a.get('name', ''))), re.I)]
        if settings.get('client') == 'wireguard':
            tunnels = [a for a in adapters if wg_state == 'healthy' and a.get('Status') == 'Up'
                       and str(a.get('Name', '')).casefold() == wg_row['interface'].casefold()]
        names = {a.get('Name', a.get('name')) for a in tunnels} - {None}
        indices = {a.get('ifIndex') for a in tunnels if type(a.get('ifIndex')) is int}
        addresses = set()
        for row in dns_rows:
            for family in (4, 6):
                for value in row.get('addresses', []):
                    try:
                        if ipaddress.ip_address(value).version == family:
                            addresses.add(value)
                            break
                    except ValueError:
                        pass
        routes = [r for r in evidence('extra.target_route') if r.get('destination') in addresses]
        measured = [r for r in routes if not r.get('error') and (r.get('interface') or type(r.get('interface_index')) is int)]
        mismatched = [r for r in measured if r.get('interface') not in names and r.get('interface_index') not in indices or re.search(r'REJECT|BLACKHOLE', r.get('flags', ''), re.I)]
        if settings.get('client') == 'wireguard':
            mismatched = [r for r in measured if (r.get('interface') and str(r['interface']).casefold() not in {n.casefold() for n in names})
                          or (type(r.get('interface_index')) is int and r['interface_index'] not in indices)
                          or re.search(r'REJECT|BLACKHOLE', r.get('flags', ''), re.I)] if wg_state == 'healthy' else []
        route_ok = dns_ok and bool(addresses) and addresses <= {r.get('destination') for r in measured} and not mismatched
        route_ok = route_ok and (wg_state == 'healthy' if settings.get('client') == 'wireguard' else True)
        add('tun_route', '目标地址的 TUN 选路', 'fail' if mismatched else 'pass' if route_ok else 'unknown',
            '所检查的目标地址经系统选择隧道接口' if route_ok else '目标地址存在非隧道选路' if mismatched else '目标选路证据不完整', routes,
            '在所选 WireGuard 隧道核对 AllowedIPs、隧道激活状态与 IPv6 路由，再复检；不会在这里改动私钥。' if settings.get('client') == 'wireguard' else '在代理客户端核对 TUN、自动路由和 IPv6 规则，再重新检测。', ['每个目标及地址族抽样一个解析地址；不等于进程全流量证明。'])
    clock = raw.get('extra.clock', {})
    add('clock', '系统时钟准确性', 'fail' if clock.get('status') == 'warn' else clock.get('status', 'unknown'), clock.get('summary', '尚未取得多个可信连接的日期样本'),
        evidence('extra.clock'), '启用系统自动设置时间并同步；时区不同不等于时钟错误。', ['HTTPS 日期比较不是 NTP 校时。'])
    if usage != 'web':
        configs = evidence('extra.config')
        indices = [0, 1] if usage == 'both' else [1] if usage == 'cli' else [0]
        chosen = [configs[i] for i in indices if i < len(configs)]
        valid = len(chosen) == len(indices) and all(c.get('exists') is False or c.get('valid') is True for c in chosen)
        invalid = any(c.get('valid') is False for c in chosen)
        add('config', '所选应用配置可读取', 'fail' if invalid else 'pass' if valid else 'unknown',
            '所选配置格式有效，或未创建可选文件' if valid else '所选应用配置损坏' if invalid else '所选应用配置未能读取', chosen,
            '先备份再修复 JSON；只有明确权限拒绝时才申请该文件的读取权限。')
    if usage in ('cli', 'both'):
        cli = first('extra.cli_env')
        cloud = [k for k in ('bedrock', 'vertex', 'foundry') if cli.get(k)]
        actual_provider = cloud[0] if len(cloud) == 1 else 'conflict' if cloud else 'custom' if cli.get('custom_endpoint') else 'anthropic'
        provider_ok = bool(cli) and actual_provider == settings['provider']
        add('provider', 'Code 接口提供方', 'pass' if provider_ok else 'fail' if cli else 'unknown',
            '所检查配置符合提供方目标' if provider_ok else '实际提供方与目标不同或存在冲突',
            [{'expected': settings['provider'], 'actual': actual_provider if cli else None}],
            '在 Code 用户或组织配置中仅保留所选提供方；EnvScope 不替换凭据和接口。')
        proxy_ok = bool(cli) and (not cli.get('proxy_configured') if mode != 'http_proxy' else
                                 cli.get('proxy_configured') and cli.get('proxy_valid') and cli.get('proxy_scheme') in ('http', 'https')
                                 and 'api.anthropic.com' not in cli.get('proxy_bypass', {}).get('target_matches', []) and not cli.get('proxy_bypass', {}).get('all_hosts'))
        if mode == 'http_proxy':
            expected_proxy = settings.get('target_proxy') or next((r.get('proxy_endpoint') for r in path_rows if r.get('proxy_endpoint')), '')
            proxy_ok = proxy_ok and bool(expected_proxy) and (cli.get('proxy_endpoint') or '').rstrip('/') == expected_proxy.rstrip('/')
        add('cli_path', 'Code 连接配置符合目标', 'pass' if proxy_ok else 'fail' if cli else 'unknown',
            'Code 用户配置与当前进程环境符合连接目标' if proxy_ok else 'Code 的代理配置与目标不一致',
            [{'expected': mode, 'configured': cli.get('proxy_configured'), 'proxy_scheme': cli.get('proxy_scheme'), 'endpoint_matches': bool(proxy_ok)}],
            '审核修复方案后保存用户配置，重开 Code 会话。系统或终端继承的代理变量需要在其来源处理。',
            ['项目及组织配置仍可能覆盖用户配置；未启动 Code 验证实际请求。'])
        auth = settings['auth_mode']
        auth_ok = bool(cli) and (auth == 'api_key' and cli.get('api_key_present') and not cli.get('auth_token_present') or
                               auth == 'subscription' and not cli.get('api_key_present') and not cli.get('auth_token_present') and actual_provider == 'anthropic')
        add('auth', 'Code 认证配置', 'pass' if auth_ok else 'fail' if auth in ('api_key', 'subscription') and cli else 'unknown',
            ('已找到 API Key 配置；尚未验证密钥' if auth == 'api_key' else '未发现覆盖订阅登录的所列认证变量；实际登录仍需确认') if auth_ok else '认证配置与所选方式不一致' if auth in ('api_key', 'subscription') else '请在 Code 中确认登录或云平台认证',
            [{'expected': auth, 'api_key_present': cli.get('api_key_present'), 'auth_token_present': cli.get('auth_token_present')}],
            '订阅用户在 Code 内登录；API 用户在本机或密钥管理器配置凭据；云用户按组织的提供方流程认证。不要将密钥填入 EnvScope。')
    if settings['ipv6_mode'] != 'observe':
        rows = evidence('http.ipv6')
        if settings['ipv6_mode'] == 'disabled':
            ok = first('baseline.ipv6').get('checked_interfaces_disabled') is True
            # An observed IPv6 response contradicts the disabled expectation.
            contradiction = any(r.get('ip') for r in rows)
            ok = ok and not contradiction
        else:
            ok = raw.get('http.ipv6', {}).get('status') == 'pass' and bool(settings.get('allowed_ipv6'))
            contradiction = raw.get('http.ipv6', {}).get('status') == 'fail'
        add('ipv6', 'IPv6 符合明确目标', 'pass' if ok else 'fail' if contradiction else 'unknown',
            '所列 IPv6 配置或出口符合目标' if ok else 'IPv6 观测与目标冲突' if contradiction else '缺少 IPv6 目标的验证证据',
            [{'expected': settings['ipv6_mode'], **first('baseline.ipv6')}]+rows,
            '按所选目标在客户端或系统中配置 IPv6 后复检。超时不能证明 IPv6 已关闭。')
    return results
