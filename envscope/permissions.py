"""Scoped OS settings and manual steps after a measured access denial."""
import os
from pathlib import Path
import platform
import subprocess

from .assessment import denied
from .observation_errors import error_evidence, inventory_errors

CAPABILITIES = {
    'network-read': ('读取网卡、DNS 与系统选路', ('system.inventory', 'baseline.dns', 'baseline.tun', 'baseline.ipv6', 'target.tun_route', 'extra.target_route', 'extra.dns_resolution')),
    'process-read': ('读取所选连接工具的运行状态', ('system.inventory', 'baseline.proxy', 'target.wireguard')),
    'region-read': ('读取当前时区与地区格式', ('system.inventory', 'baseline.timezone', 'baseline.locale')),
    'application-read': ('读取 Claude 本地配置与资料目录', ('extra.config', 'target.config', 'extra.profile', 'extra.account', 'extra.storage', 'extra.desktop', 'baseline.language')),
    'code-read': ('读取 Code 用户配置的格式与环境项存在性', ('extra.cli_env', 'target.config', 'extra.config')),
    'hosts-read': ('读取 hosts 中与 Claude 有关的记录', ('extra.hosts',)),
    'proxy-read': ('读取当前用户的系统代理配置', ('extra.proxy_layers', 'target.path')),
}


def has_error(value, code):
    if isinstance(value, dict):
        return value.get('error') == code or any(has_error(v, code) for v in value.values())
    return isinstance(value, list) and any(has_error(v, code) for v in value)


def capabilities(finding, usage):
    key = finding['id']
    if key == 'system.inventory':
        failures = {}
        for value in finding.get('evidence', []):
            if isinstance(value, dict):
                failures.update(inventory_errors(value))
        ids = set()
        for name, value in failures.items():
            if denied(value):
                ids.add('region-read' if name in ('timezone', 'locale', 'language') else
                        'process-read' if name == 'known_clients' else
                        'application-read' if name == 'desktop_packages' else 'network-read')
        return sorted(ids) or ['network-read']
    if key == 'target.config':
        return ['code-read'] if usage == 'cli' else ['application-read', 'code-read'] if usage == 'both' else ['application-read']
    return [name for name, (_, checks) in CAPABILITIES.items() if key in checks]


def os_action(capability, system, home, profile):
    root = Path(os.environ.get('SystemRoot', 'C:/Windows'))
    path = home / '.claude' if capability == 'code-read' else root / 'System32/drivers/etc/hosts' if capability == 'hosts-read' else profile
    if capability in ('application-read', 'code-read', 'hosts-read'):
        if system == 'Darwin':
            if capability == 'hosts-read':
                return None, ['系统拒绝读取 /etc/hosts。请让管理员核对该文件的读取权限及组织策略。不要开放写入权限。']
            return ['/usr/bin/open', 'x-apple.systempreferences:com.apple.preference.security?Privacy_FilesAndFolders'], [
                '在隐私与安全性 → 文件与文件夹中核对 EnvScope 的相关目录权限。',
                '若列表没有本软件或仍被拒绝，核对文件所有者与只读权限；完全磁盘访问只在确实需要读取受保护目录时考虑。',
                '系统提示重新打开时，请退出再打开 EnvScope 并检测。']
        return [str(root / 'explorer.exe'), '/select,', str(path)], [
            '在所选文件或目录的属性 → 安全中核对当前用户的读取权限。',
            '组织管理的权限由管理员处理；无需给整个应用永久管理员权限。']
    if capability == 'process-read':
        return ([str(root / 'System32/mmc.exe'), str(root / 'System32/services.msc')] if system == 'Windows' else
                ['/usr/bin/open', '/System/Applications/Utilities/Activity Monitor.app']), [
            '核对连接工具或所选隧道服务是否运行，以及其所属用户。',
            '进程或服务读取被限制时，请管理员授予所需读取权限；不要改动 VPN 凭据。']
    if capability == 'region-read':
        uri = 'ms-settings:dateandtime' if system == 'Windows' else 'x-apple.systempreferences:com.apple.Date-Time-Settings.extension'
        steps = ['核对日期与时间以及地区设置。读取被组织策略限制时，请管理员处理。']
    else:
        uri = ('ms-settings:network-proxy' if capability == 'proxy-read' else 'ms-settings:network-status') if system == 'Windows' else 'x-apple.systempreferences:com.apple.Network-Settings.extension'
        steps = ['核对当前网络及代理配置。系统网络读取没有通用的“允许”开关，若组织策略拒绝读取，请管理员核对对应权限。',
                 '打开设置不会自行授予权限或修改连接。返回后将重新检测并保留实际结果。']
    return ([str(root / 'explorer.exe'), uri] if system == 'Windows' else ['/usr/bin/open', uri]), steps


def permission_help(report, params, home, profile, confirmed=False, runner=subprocess.Popen, system=None):
    if set(params) != {'report_id', 'finding_id'} or not report or params['report_id'] != report.get('report_id'):
        return {'state': 'retest_required', 'reason': '先完成本轮检测，再处理本次明确拒绝的权限。'}
    finding = next((f for f in report.get('findings', []) if f['id'] == params['finding_id']), None)
    if not finding or finding.get('scope') == 'not-selected' or not denied(finding.get('evidence', [])):
        raise ValueError('这项没有明确的权限拒绝证据，不申请额外权限')
    system = system or platform.system()
    base = {'scope': 'read', 'permission_granted': False, 'report_id': report['report_id'],
            'finding_id': finding['id'], 'capabilities': [], 'affected_checks': []}
    if has_error(finding['evidence'], 'policy_denied'):
        return {**base, 'state': 'manual', 'error': 'policy_denied', 'reason': '组织策略拒绝了读取，请联系管理员处理；不会反复请求管理员权限。',
                'manual_steps': ['向设备管理员提供失败的检查名称和 policy_denied 代码，处理后重新检测。']}
    if system not in ('Windows', 'Darwin'):
        return {**base, 'state': 'unavailable', 'reason': '当前仅支持 Windows 与 macOS。'}
    ids = capabilities(finding, report.get('usage'))
    entries = [(name, *os_action(name, system, Path(home), Path(profile))) for name in ids]
    base['capabilities'] = [{'id': name, 'label': CAPABILITIES[name][0], 'access': 'read',
                             'os_action': 'open_settings' if command else 'manual'} for name, command, _ in entries]
    base['affected_checks'] = sorted({check for name in ids for check in CAPABILITIES[name][1]})
    steps = list(dict.fromkeys(step for _, _, values in entries for step in values))
    base['manual_steps'] = steps or ['核对该项证据中的读取位置及权限，由资料所有者或设备管理员处理后复检。']
    commands = list(dict.fromkeys(tuple(command) for _, command, _ in entries if command))
    if not commands:
        return {**base, 'state': 'manual', 'reason': ' '.join(base['manual_steps'])}
    if confirmed is not True:
        return {**base, 'state': 'confirmation_required', 'reason': '；'.join(CAPABILITIES[name][0] for name in ids) +
                '。将打开对应系统入口供核对，不修改配置或导出凭据。返回后自动复检一次。'}
    try:
        for command in commands:
            runner(list(command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except OSError as exc:
        return {**base, **error_evidence(exc, 'open_settings'), 'state': 'unavailable',
                'reason': '未能打开系统入口。' + ' '.join(base['manual_steps'])}
    return {**base, 'state': 'opened', 'reason': ' '.join(base['manual_steps']), 'recheck_on_return': True}
