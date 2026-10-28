"""Reviewed region changes. No writes happen while collecting diagnostics."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import time
from urllib.parse import quote
from urllib.request import Request, build_opener, ProxyHandler

from .controller import NoRedirects, validate_controller
from .discovery import config_documents
from .region_profiles import profile, profiles
from .target_environment import fingerprint


def current_region(inventory):
    return {'timezone': inventory.get('network', {}).get('timezone_id') or inventory.get('timezone_iana') or '',
            'locale': inventory.get('locale') or ''}


def _run(command, timeout=55):
    return subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                          timeout=timeout, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def set_system_value(system, key, value, runner=_run):
    # Only validated preset IDs or values read in our own recovery record enter commands.
    if key == 'timezone':
        pattern = r'[A-Za-z0-9 +_-]{1,100}' if system == 'Windows' else r'[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+){0,3}'
        if not re.fullmatch(pattern, value):
            raise ValueError('无法安全写入此时区，请在系统设置中处理')
    elif key == 'locale':
        if not re.fullmatch(r'[A-Za-z]{2,3}[-_][A-Za-z0-9_-]{2,30}', value):
            raise ValueError('地区格式包含自定义扩展，请在系统设置中处理')
    else:
        raise ValueError('未知系统配置')
    if system == 'Windows':
        root = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32'
        powershell = str(root / 'WindowsPowerShell/v1.0/powershell.exe')
        if key == 'timezone':
            executable = str(root / 'tzutil.exe')
            result = runner([executable, '/s', value])
            if result.returncode == 0:
                return
            # Only tzutil is elevated; user culture must remain in the original user's session.
            script = "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath '" + executable.replace("'", "''") + "' -ArgumentList '/s \"" + value + "\"' -Verb RunAs -WindowStyle Hidden -PassThru -Wait; exit $p.ExitCode"
        else:
            script = "$ErrorActionPreference='Stop'; Set-Culture -CultureInfo '" + value.replace('_', '-') + "'"
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        result = runner([powershell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded])
    elif system == 'Darwin':
        if key == 'timezone':
            command = '/usr/sbin/systemsetup -settimezone ' + value
            result = runner(['/usr/bin/osascript', '-e', 'do shell script ' + json.dumps(command) + ' with administrator privileges'])
        else:
            result = runner(['/usr/bin/defaults', 'write', '-g', 'AppleLocale', '-string', value.replace('-', '_')])
    else:
        raise ValueError('此系统不支持自动配置')
    if result.returncode != 0:
        raise ValueError('系统未允许或未完成修改；请在日期与时间 / 语言与地区设置中手动处理后复检')


class NodeController:
    """Only existing Selector members on a configured loopback control API."""
    def __init__(self, origin, secret=''):
        self.origin = validate_controller(origin)
        if not isinstance(secret, str) or len(secret) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise ValueError('控制接口认证格式无效')
        self.headers = {'Accept': 'application/json'}
        if secret:
            self.headers['Authorization'] = 'Bearer ' + secret
        self.identity = hashlib.sha256((self.origin + '\0' + secret).encode()).hexdigest()
        self.opener = build_opener(ProxyHandler({}), NoRedirects())

    def request(self, path, data=None):
        headers = {**self.headers, 'Content-Type': 'application/json'}
        request = Request(self.origin + path, headers=headers, data=None if data is None else json.dumps(data).encode(),
                          method='GET' if data is None else 'PUT')
        try:
            with self.opener.open(request, timeout=4) as response:
                raw = response.read(1048577)
                if response.status not in (200, 204) or len(raw) > 1048576:
                    raise ValueError('invalid controller response')
            return json.loads(raw) if raw else {}
        except (OSError, ValueError) as error:
            raise ValueError('控制接口未授权、不可达或响应无效；请在代理客户端启用本机控制接口并复检') from error

    def groups(self):
        payload = self.request('/proxies')
        nodes = payload.get('proxies') if isinstance(payload, dict) else None
        if not isinstance(nodes, dict) or len(nodes) > 20000:
            raise ValueError('节点目录无法识别')
        result = []
        for name, item in nodes.items():
            if not isinstance(item, dict) or item.get('type') != 'Selector' or not isinstance(item.get('all'), list):
                continue
            members = []
            for member in item['all']:
                node = nodes.get(member) if isinstance(member, str) else None
                if (isinstance(node, dict) and isinstance(node.get('type'), str) and node['type']
                        and node['type'].lower() not in ('direct', 'reject', 'rejectdrop', 'pass', 'block', 'selector', 'urltest', 'fallback', 'loadbalance')
                        and 'all' not in node and 'now' not in node and len(member) <= 240 and not any(ord(c) < 32 for c in member)):
                    members.append(member)
            if members and isinstance(name, str) and len(name) <= 240 and not any(ord(c) < 32 for c in name):
                result.append({'name': name, 'now': item.get('now'), 'nodes': members,
                               'members': [n for n in item['all'] if isinstance(n, str) and n in nodes]})
        return result

    def select(self, group, node, expected, restore=False):
        row = next((g for g in self.groups() if g['name'] == group), None)
        if not row or row['now'] != expected or node not in row['members' if restore else 'nodes']:
            raise ValueError('节点或代理组已变化，请重新读取并生成方案')
        self.request('/proxies/' + quote(group, safe=''), {'name': node})
        row = next((g for g in self.groups() if g['name'] == group), None)
        if not row or row['now'] != node:
            raise ValueError('节点切换后读回不一致，请在代理客户端核对当前选择')


def discover_controller(home=None, system=None, environ=None):
    env = os.environ if environ is None else environ
    if env.get('ENVSCOPE_CONTROLLER_URL'):
        return NodeController(env['ENVSCOPE_CONTROLLER_URL'], env.get('ENVSCOPE_CONTROLLER_SECRET', ''))
    candidates = {}
    for document in config_documents(home, system, env):
        address = re.search(r'^external-controller:\s*["\']?([^\s"\'#]+)', document, re.M)
        if not address:
            continue
        # Never invent a writable default endpoint, and never contact a remote controller.
        try:
            origin = validate_controller('http://' + address[1])
        except ValueError:
            continue
        secret = re.search(r'^secret:\s*["\']?([^\s"\'#]*)', document, re.M)
        candidates[origin] = secret[1] if secret else env.get('ENVSCOPE_CONTROLLER_SECRET', '')
    if len(candidates) != 1:
        raise ValueError('没有唯一可控制的本机接口。请在客户端启用 loopback HTTP 控制接口；多个内核时用 ENVSCOPE_CONTROLLER_URL 明确选择')
    origin, secret = next(iter(candidates.items()))
    return NodeController(origin, secret)


class RegionSetup:
    def __init__(self, store, reader, home, system=None, writer=None, controller=None):
        self.store, self.reader, self.home = store, reader, home
        self.system = system or platform.system()
        self.writer = writer or (lambda k, v: set_system_value(self.system, k, v))
        self.controller = controller or (lambda: discover_controller(self.home, self.system))
        self.plans = {}
        self._recovery = None

    def _save_recovery(self, record):
        self.store._write('region-recovery.private.json', record)
        self._recovery = json.loads(json.dumps(record))

    def options(self):
        value = {'profiles': profiles(self.system), 'observed': current_region(self.reader()), 'groups': []}
        try:
            value['groups'] = self.controller().groups()
            value['node_reason'] = '仅列出可手动选择的现有节点；名称不证明出口国家。切换可能影响同组的其他应用。'
        except (ValueError, OSError):
            value['node_reason'] = '未能读取可控制节点。在代理客户端启用本机 HTTP 控制接口，或手动选择目标地区节点后复检。'
        return value

    def prepare(self, report, components, group='', node=''):
        from .remedies import SolutionPlans
        from .regions import region_finding, PARTIAL
        settings = self.store.settings()
        pending = self.recovery()
        if pending and pending.get('state') in ('in_progress', 'partial'):
            return {'state': 'guided', 'reason': '上次地区修改尚未完成。先在恢复记录中核对并恢复原值，再生成新方案；未覆盖原记录。'}
        if (not SolutionPlans._current(report) or not settings.get('environment_confirmed') or
                report.get('environment', {}).get('fingerprint') != fingerprint(settings)):
            return {'state': 'retest_required', 'reason': '请先按当前目标检测，再预览地区配置'}
        declared = region_finding([], settings)
        known = next((f for f in report['findings'] if f['id'] == 'target.region'), {})
        if declared.status.value == 'fail' or not settings.get('usage_country') or settings.get('usage_country') in PARTIAL or known.get('status') == 'fail':
            return {'state': 'blocked', 'reason': '官方地区条件不合格或实际地区未确认。改时区和节点不能改变使用资格，请核对官方名单。'}
        selected = profile(settings.get('region_profile'), self.system)
        if not selected:
            return {'state': 'guided', 'reason': '先在目标设置选择期望的地区与城市；自定义目标请在系统设置中手动修改'}
        if not isinstance(components, list) or not components or len(components) != len(set(components)) or set(components) - {'timezone', 'locale', 'node'}:
            raise ValueError('请选择需要修改的时区、地区格式或节点')
        before, changes, effects = current_region(self.reader()), {}, []
        for key, label in (('timezone', '系统时区'), ('locale', '当前用户地区格式')):
            if key in components and before[key] != selected[key]:
                if not before[key]:
                    raise ValueError('未读取到原' + label + '，无法建立恢复记录；请先处理读取问题')
                changes[key] = selected[key]
                effects.append(label + '：' + before[key] + ' → ' + selected[key])
        controller = None
        if 'node' in components:
            if settings.get('connection_mode') == 'direct':
                raise ValueError('当前目标为直连，请先确认实际连接方式')
            controller = self.controller()
            row = next((r for r in controller.groups() if r['name'] == group), None)
            if not row or node not in row['nodes'] or not isinstance(row['now'], str):
                raise ValueError('请选择当前代理组内可用的具体节点')
            if row['now'] != node:
                changes['node'] = node
                before['node'] = row['now']
                effects.append('代理组 ' + group + '：' + row['now'] + ' → ' + node + '；影响该组的后续新连接，不强制断开现有连接')
        if not changes:
            return {'state': 'guided', 'reason': '所选配置已经一致，无需写入；出口仍以实际复检为准'}
        token = secrets.token_urlsafe(20)
        record = {'before': before, 'changes': changes, 'group': group, 'identity': controller.identity if controller else None,
                  'fingerprint': fingerprint(settings), 'report_id': report['report_id'], 'deadline': time.monotonic() + 90}
        self.plans = {token: record}
        return {'state': 'planned', 'plan_id': token, 'effects': effects,
                'reason': '确认后修改并读回。时区可能触发系统授权；地区格式需重开应用。保留原值供撤销，不修改系统显示语言或实际所在地。自动时区服务可能再次覆盖手动值，需在系统设置核对。'}

    def apply(self, token, report, confirmed):
        if confirmed is not True:
            return {'state': 'confirmation_required', 'reason': '先核对具体改动'}
        plan = self.plans.get(token) if isinstance(token, str) else None
        if (not plan or time.monotonic() > plan['deadline'] or not report or plan['report_id'] != report['report_id']
                or plan['fingerprint'] != fingerprint(self.store.settings())):
            return {'state': 'retest_required', 'reason': '方案过期或目标已改变，请重新检测'}
        if any(current_region(self.reader()).get(k) != plan['before'].get(k) for k in plan['changes'] if k != 'node'):
            return {'state': 'retest_required', 'reason': '系统设置已在预览后改变，请重新检测'}
        controller = self.controller() if 'node' in plan['changes'] else None
        if controller and controller.identity != plan['identity']:
            return {'state': 'retest_required', 'reason': '控制接口已改变，请重新检测'}
        del self.plans[token]
        # Persist intent before the first mutation, so an interrupted process leaves recovery instructions.
        receipt = {k: plan[k] for k in ('before', 'changes', 'group', 'identity')}
        receipt.update(state='in_progress', applied=[])
        self._save_recovery(receipt)
        steps = []
        for key in ('node', 'timezone', 'locale'):
            if key not in plan['changes']:
                continue
            try:
                if key == 'node':
                    controller.select(plan['group'], plan['changes'][key], plan['before'][key])
                else:
                    self.writer(key, plan['changes'][key])
                    if current_region(self.reader())[key].replace('_', '-').lower() != plan['changes'][key].replace('_', '-').lower():
                        raise ValueError('系统读回尚未符合目标；请重开应用并复检，不能据命令成功判为完成')
                receipt['applied'].append(key)
                self._save_recovery(receipt)
                steps.append({'item': key, 'state': 'verified', 'reason': '配置已读回；网络出口另行复检'})
            except (ValueError, OSError, subprocess.TimeoutExpired):
                steps.append({'item': key, 'state': 'manual', 'reason': '未确认修改完成，后续步骤已停止。按恢复记录核对实际值；权限取消、超时或自动时区覆盖时请在系统 / 代理客户端中处理。'})
                break
        receipt['state'] = 'completed' if len(receipt['applied']) == len(plan['changes']) else 'partial'
        self._save_recovery(receipt)
        return {'state': receipt['state'], 'steps': steps, 'needs_retest': True, 'recovery': self.public_recovery(),
                'reason': '所列配置已写入并读回，现在重新检测真实出口和使用条件。' if receipt['state'] == 'completed' else '部分设置未完成，已停止；红色项目按手动步骤处理后复检。'}

    def recovery(self):
        record = self._recovery if self.store.memory else self.store._read('region-recovery.private.json', None)
        if not isinstance(record, dict) or record.get('state') == 'restored':
            return None
        return record

    def public_recovery(self):
        record = self.recovery()
        return {k: v for k, v in record.items() if k != 'identity'} if record else None

    def undo(self, confirmed):
        if confirmed is not True:
            return {'state': 'confirmation_required'}
        record = self.recovery()
        if not record:
            return {'state': 'guided', 'reason': '没有待恢复的地区配置记录'}
        # Compare every value immediately before undo; never overwrite a later user edit.
        results = []
        for key in ('locale', 'timezone', 'node'):
            if key not in record['changes']:
                continue
            try:
                if key == 'node':
                    controller = self.controller()
                    if controller.identity != record['identity']:
                        raise ValueError('控制接口变化')
                    row = next((r for r in controller.groups() if r['name'] == record['group']), None)
                    current = row['now'] if row else None
                else:
                    current = current_region(self.reader())[key]
                if current == record['before'][key]:
                    continue
                if current != record['changes'][key]:
                    raise ValueError('配置已由其他操作改动')
                if key == 'node':
                    controller.select(record['group'], record['before'][key], current, restore=True)
                else:
                    self.writer(key, record['before'][key])
                    if current_region(self.reader())[key] != record['before'][key]:
                        raise ValueError('恢复值未读回')
                results.append({'item': key, 'state': 'restored'})
            except (KeyError, ValueError, OSError, subprocess.TimeoutExpired):
                return {'state': 'partial', 'steps': results, 'needs_retest': True, 'reason': '未覆盖后续改动或未确认恢复，保留记录。请对照原值在系统 / 代理客户端手动恢复。'}
        record['state'] = 'restored'
        self._save_recovery(record)
        return {'state': 'completed', 'needs_retest': True, 'reason': '已读回原配置；检测目标保留，如需更换目标请重新确认'}
