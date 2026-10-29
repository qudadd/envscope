"""Explicit check selection and dependency closure for real selective probes."""
from .model import Finding, Status

TARGETS = {
    'target.region': ('Claude 官方地区支持', ('http.egress', 'baseline.country')),
    'target.dns': ('所选用途的域名解析', ('extra.dns_resolution',)),
    'target.tls': ('所选用途的证书校验', ('baseline.reachability',)),
    'target.service': ('所选用途的服务连接', ('baseline.reachability',)),
    'target.clock': ('系统时间准确性', ('extra.clock',)),
    'target.path': ('所选连接路径', ('extra.proxy_layers', 'http.egress')),
    'target.config': ('所选客户端配置', ('extra.config',)),
    'target.cli_path': ('Code 的实际连接配置', ('extra.cli_env', 'http.egress')),
    'target.provider': ('Code 服务提供方', ('extra.cli_env',)),
    'target.auth': ('Code 认证配置', ('extra.cli_env',)),
    'target.ipv6': ('IPv6 目标条件', ('baseline.ipv6', 'http.ipv6')),
    'target.tun_route': ('目标地址的 TUN 选路', ('baseline.tun', 'extra.dns_resolution', 'extra.target_route')),
}
MEASUREMENTS = {
    'system.inventory': '系统只读资料', 'http.egress': 'HTTP IPv4 出口交叉验证', 'http.ipv6': 'HTTP IPv6 出口',
    'udp.stun': '原生 UDP STUN 出口', 'browser.webrtc': '当前浏览器 WebRTC',
    'browser.http_v4': '当前浏览器 HTTP IPv4', 'browser.http_v6': '当前浏览器 HTTP IPv6',
    'dns.leak': '权威 DNS 出口（本版未支持）', 'network.route': '进程流量关联（本版未支持）',
}
DEPENDENCIES = {k: set(v[1]) for k, v in TARGETS.items()}
DEPENDENCIES.update({
    'baseline.country': {'http.egress'}, 'baseline.ip_stability': {'http.egress', 'http.ipv6'},
    'baseline.webrtc': {'udp.stun', 'browser.webrtc', 'http.egress', 'http.ipv6'},
    'baseline.ipv6': {'http.ipv6'}, 'udp.stun': {'http.egress', 'http.ipv6'},
    'browser.webrtc': {'browser.http_v4', 'browser.http_v6'},
    'extra.tls': {'baseline.reachability'}, 'extra.timing': {'baseline.reachability'},
    'extra.clock': {'baseline.reachability'},
})


def ids():
    from .claude_checks import ITEMS
    from .extended import CHECKS
    return set(TARGETS) | set(MEASUREMENTS) | {'device.environment', 'browser.environment'} | {
        'baseline.' + row[0] for row in ITEMS} | {'extra.' + row[0] for row in CHECKS}


def validate_selection(value):
    if value is None:
        return None
    if (not isinstance(value, list) or not value or len(value) > 80 or any(not isinstance(v, str) for v in value)
            or len(set(value)) != len(value) or set(value) - ids()):
        raise ValueError('请选择有效且不重复的检查项目')
    return sorted(value)


def resolve(value):
    value = validate_selection(value)
    if value is None:
        return ids()
    result = set(value) | {'system.inventory'}
    while True:
        expanded = result | set().union(*(DEPENDENCIES.get(k, set()) for k in result))
        if expanded == result:
            return result
        result = expanded


def scope_findings(findings, selected):
    enabled = resolve(selected) | {'target.region'}  # physical-region declaration always remains a guard
    if selected is None:
        return findings
    return [f if f.id in enabled else Finding(f.id, f.title, Status.SKIPPED, '本次未勾选，未用于本轮判断',
                                            'not-selected', suggestion='勾选此项并检测后，才能得到结论。') for f in findings]


def selection_info(selected):
    if selected is None or set(selected) == ids():
        return {'mode': 'full', 'selected': sorted(ids()), 'dependencies': []}
    enabled = resolve(selected)
    return {'mode': 'selected', 'selected': sorted(selected), 'dependencies': sorted(enabled - set(selected)),
            'note': '只运行所选项目及其依赖。系统资料和共用配置文件可能一次读取；未选项目不会判通过。完整环境结论仍要求全部必需项目的证据。'}


def problem_prefixes(checks):
    """Fixed mapping: selection must never authorize unrelated repairs."""
    from .claude_checks import CHECK_PROBLEMS
    mapping = {
        'extra.config': ('config.', 'config_access.', 'config_read.'),
        'target.config': ('config.', 'config_access.', 'config_read.'),
        'extra.cli_env': ('cli.', 'target.cli_path', 'target.provider', 'target.auth'),
        'target.cli_path': ('cli.socks', 'cli.proxy_format', 'cli.bypass', 'target.cli_path'),
        'target.provider': ('cli.providers', 'cli.endpoint', 'target.provider'),
        'target.auth': ('cli.auth_choice', 'target.auth'),
        'extra.cli_paths': ('cli.installation', 'cli.multiple_paths'),
        'extra.proxy_listener': ('proxy.listener',), 'extra.proxy_bypass': ('cli.bypass',),
        'extra.proxy_layers': ('proxy.',), 'target.path': ('proxy.', 'target.path'),
        'extra.hosts': ('hosts.',), 'extra.clock': ('clock.',), 'target.clock': ('clock.',),
        'extra.tls': ('network.certificate',), 'target.tls': ('network.certificate',),
        'target.service': ('service.', 'network.'), 'http.egress': ('network.',),
        'extra.desktop': ('desktop.installation',), 'extra.storage': ('storage.',),
        'extra.account': ('account.',), 'target.region': ('target.region',),
        'target.dns': ('network.dns',), 'extra.dns_resolution': ('network.dns',),
        'target.tun_route': ('target.tun_route', 'startup.tun'), 'extra.runtime_tun': ('startup.tun',),
        'target.ipv6':('target.ipv6','policy.http.ipv6','policy.browser.http_v6'),
    }
    prefixes = set()
    for key in checks:
        prefixes.update(CHECK_PROBLEMS.get(key.removeprefix('baseline.'), ()) if key.startswith('baseline.') else mapping.get(key, ()))
    return tuple(sorted(prefixes))


def repair_options(report):
    """Every displayed check has a clear action or a specific manual next step."""
    from .check_catalog import check_catalog
    catalog = {r['id']: r for r in check_catalog()}
    annotations = {r['id']: r for r in report.get('assessment', {}).get('items', [])}
    result = {}
    for f in report['findings']:
        key = f['id']
        note = annotations.get(key, {})
        problems = [p for p in report['diagnosis']['problems'] if p['id'].startswith(problem_prefixes([key]))]
        steps = [step for p in problems for step in p.get('steps', [])]
        if not steps:
            steps = [note.get('next_step') or f.get('suggestion') or catalog.get(key, {}).get('next_step') or '按所列证据核对实际使用的客户端；处理后重新检测本项。']
        action = 'region' if key in ('baseline.timezone', 'baseline.locale', 'baseline.country') else 'solution' if any(p.get('repair') for p in problems) else 'manual'
        if key in ('target.ipv6','baseline.ipv6','target.dns','extra.dns_resolution') and f['status']=='fail':
            action='solution'
        if note.get('action') == 'permission-help':
            action = 'permission'
        needed = f['status'] == 'fail' or note.get('state') == 'unsupported' or f['status'] in ('warn', 'unknown') and note.get('state') not in ('not_applicable', 'informational')
        if key == 'dns.leak':
            steps = ['本版本尚未接入权威 DNS 出口收集服务，授予更多权限也不能补齐。', '需要验证时，使用自己信任的权威 DNS 检测服务触发随机域名查询，核对其看到的解析来源；系统 DNS 地址不能代替此证据。', '此项保持未验证，不要求为了通过检查而修改系统 DNS。']
        elif key == 'network.route':
            steps = ['本版本尚未实现 Claude 进程与数据包的完整关联。', '需要核实时，在本机用 Wireshark 等工具观察实际 Claude 会话，并结合系统进程连接信息核对接口与目标；不要上传含会话内容的抓包。', '本项保持未验证；系统选路和 TUN 网卡仅提供辅助信息。']
        elif key=='baseline.language' and needed:
            system=next(iter(next((row for row in report['findings'] if row['id']=='system.inventory'),{}).get('evidence',[])),{}).get('platform')
            if system=='Windows':
                action='manual'
                steps=['Windows 尚未提供 Claude 专用语言偏好的自动写入接口。',
                       '在 Claude 的设置中选择它实际支持的语言；若缺少对应选项，先确认应用版本及本地化支持。',
                       '在实际界面确认语言；系统显示语言不能作为 Claude 语言通过的证据。']
        if f['scope'] == 'not-selected':
            action, needed, steps = 'check', False, ['本次未勾选。先检测本项，再根据实际结果决定是否修改。']
        elif f['status'] == 'pass':
            action, needed = 'none', False
        result[key] = {'action': action, 'needs_attention': needed, 'manual': action in ('manual', 'permission') and needed,
                       'steps': list(dict.fromkeys(steps)), 'problem_ids': [p['id'] for p in problems]}
    return result
