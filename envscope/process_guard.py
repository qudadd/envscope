"""Opt-in desktop process protection. No account files, elevation or packet claims.

Only the separately approved worker can stop recognized, current-user Claude
desktop processes. Polling has a detection window and is not a firewall.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import secrets
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

from .accounts import _safe_chain
from .config_files import load_object
from .discovery import safe_local_proxy
from .event_log import append_event
from .maintenance import age
from .model import utc_now
from .remedies import SolutionPlans, _read
from .scheduler import UserScheduler
from .state import StateStore
from .target_environment import fingerprint

INTERVAL = 10
POLICY_VERSION = 2
KERNELS = {'auto': (), 'other': (), 'clash-verge': ('mihomo', 'verge-mihomo'),
           'sing-box': ('sing-box',), 'clashx': ('clashx', 'clash'),
           'shadowrocket': ('shadowrocket',), 'surge': ('surge',), 'wireguard': ()}


def desktop_path(value, home, system):
    """A same-name Code executable or arbitrary child command is not a target."""
    if not isinstance(value, str) or not value or '\x00' in value:
        return False
    if system == 'Windows':
        path = PureWindowsPath(value)
        if not path.is_absolute() or '..' in path.parts or path.name.lower() != 'claude.exe':
            return False
        roots = [PureWindowsPath(home)/'AppData/Local/Programs/Claude',
                 PureWindowsPath(home)/'AppData/Local/AnthropicClaude',
                 PureWindowsPath(os.environ.get('ProgramFiles', 'C:/Program Files'))/'Claude']
        if any(path.is_relative_to(root) for root in roots):
            return True
        apps = PureWindowsPath(os.environ.get('ProgramFiles', 'C:/Program Files'))/'WindowsApps'
        return (path.is_relative_to(apps) and len(path.relative_to(apps).parts) >= 2
                and bool(re.fullmatch(r'[a-z0-9_.-]*claude[a-z0-9_.-]*', path.relative_to(apps).parts[0], re.I)))
    if system == 'Darwin':
        path = PurePosixPath(value)
        if not path.is_absolute() or '..' in path.parts:
            return False
        for app in (PurePosixPath('/Applications/Claude.app'), PurePosixPath(home)/'Applications/Claude.app'):
            if path == app/'Contents/MacOS/Claude':
                return True
            if (path.is_relative_to(app/'Contents/Frameworks') and path.name.startswith('Claude Helper')
                    and path.parent.name == 'MacOS' and path.parent.parent.name == 'Contents'):
                return True
    return False


class NativeGuardIO:
    def __init__(self, home, system=None, ps=None, connector=None, service_reader=None):
        self.home, self.system = home, system or platform.system()
        if ps is None:
            import psutil as ps
        self.ps = ps
        self.connector = connector or socket.create_connection
        from .wireguard import WireGuardReader
        self.service_reader = service_reader or WireGuardReader(system=self.system).collect

    def legacy(self):
        from .component_inventory import Layout, mac_snapshot, windows_snapshot
        layout = Layout(self.home, self.system)
        if self.system == 'Windows': return windows_snapshot(layout)
        if self.system == 'Darwin': return mac_snapshot(layout, os.getuid(), roles=['guard'])
        raise ValueError('旧守护登记读取尚不支持此系统')

    def identity(self):
        p = self.ps.Process(os.getpid())
        return {'pid': p.pid, 'created': p.create_time(), 'exe': p.exe()}

    def alive(self, worker, executable):
        try:
            p = self.ps.Process(worker['pid'])
            return (p.create_time() == worker['created'] and p.username() == self.ps.Process().username()
                    and os.path.normcase(p.exe()) == os.path.normcase(executable)
                    and os.path.normcase(worker['exe']) == os.path.normcase(executable))
        except (self.ps.Error, OSError, ValueError, TypeError, KeyError):
            return False

    def snapshot(self):
        try:
            return self._snapshot()
        except self.ps.Error as error:
            raise OSError('进程信息读取失败') from error

    def _snapshot(self):
        own = self.ps.Process().username()
        targets, clients, unreadable = [], set(), False
        for proc in self.ps.process_iter(['pid', 'name', 'exe', 'create_time', 'username'], ad_value=None):
            item = proc.info
            name = str(item.get('name') or '').lower().removesuffix('.exe')
            if name in {n for values in KERNELS.values() for n in values}:
                clients.add(name)
            if name != 'claude' and not name.startswith('claude helper'):
                continue
            if item.get('username') not in (None, own):
                continue
            if not item.get('exe') or not item.get('username') or item.get('create_time') is None:
                unreadable = True
            elif desktop_path(item['exe'], self.home, self.system):
                targets.append({'pid': item['pid'], 'created': item['create_time'], 'exe': item['exe']})
        try:
            adapters = self.ps.net_if_stats()
        except (self.ps.Error, OSError):
            adapters = None
        return {'targets': targets, 'unreadable': unreadable, 'clients': sorted(clients),
                'wireguard': self.service_reader(),
                'interfaces': [{'name': name, 'up': value.isup is True} for name, value in adapters.items()] if adapters is not None else None}

    def listening(self, proxy):
        parts = urlsplit(proxy)
        try:
            with self.connector((parts.hostname, parts.port), timeout=1):
                return True
        except OSError:
            return False

    def stop(self, targets):
        try:
            return self._stop(targets)
        except self.ps.Error:
            return False

    def _stop(self, targets):
        # psutil also checks PID reuse for terminate/kill. Recheck our narrower
        # user/path/creation-time constraints immediately before each signal.
        pending, failed = [], False
        own = self.ps.Process().username()
        for item in targets:
            try:
                p = self.ps.Process(item['pid'])
                if (p.create_time() != item['created'] or p.exe() != item['exe']
                        or p.username() != own or not desktop_path(p.exe(), self.home, self.system)):
                    failed = True
                    continue
                p.terminate()
                pending.append(p)
            except self.ps.NoSuchProcess:
                continue
            except (self.ps.Error, OSError):
                failed = True
        _, alive = self.ps.wait_procs(pending, timeout=2)
        for p in alive:
            try:
                if p.username() == own and desktop_path(p.exe(), self.home, self.system):
                    p.kill()
                else:
                    failed = True
            except self.ps.NoSuchProcess:
                continue
            except (self.ps.Error, OSError):
                failed = True
        _, alive = self.ps.wait_procs(alive, timeout=2)
        return not failed and not alive


def validate_baseline(value):
    base = {'mode', 'proxy', 'interface', 'client'}
    if not isinstance(value, dict) or set(value) != base | ({'wireguard'} if value.get('client') == 'wireguard' else set()):
        raise ValueError('进程守护基线格式无效')
    if not all(isinstance(value[k], str) for k in base):
        raise ValueError('进程守护基线字段必须是文本')
    if value['mode'] not in ('http_proxy', 'tun') or value['client'] not in KERNELS:
        raise ValueError('进程守护连接方式无效')
    if value['mode'] == 'http_proxy':
        if not safe_local_proxy(value['proxy']) or not value['proxy'].startswith(('http://', 'https://')) or value['interface']:
            raise ValueError('守护仅支持无凭据的本机 HTTP 代理端口')
    elif (value['proxy'] or not isinstance(value['interface'], str) or not 0 < len(value['interface']) <= 200
          or any(ord(c) < 32 for c in value['interface'])):
        raise ValueError('请选择一个确切的隧道网卡')
    if value['client'] == 'wireguard':
        from .wireguard import valid_service, local_path, PREFIX
        pin = value['wireguard']
        if (value['mode'] != 'tun' or not isinstance(pin, dict) or set(pin) != {'service', 'path', 'sha256'}
                or not valid_service(pin.get('service')) or not local_path(pin.get('path'))
                or PureWindowsPath(pin['path']).name.casefold() != 'wireguard.exe'
                or not re.fullmatch('[a-f0-9]{64}', str(pin.get('sha256', '')))
                or value['interface'].casefold() != pin['service'][len(PREFIX):].casefold()):
            raise ValueError('WireGuard 守护需要核实的具体隧道服务、程序摘要和对应网卡')


def health(baseline, observed, io):
    if baseline['mode'] == 'http_proxy':
        ok = io.listening(baseline['proxy']) is True
        return ok, '批准的本机代理端口在线' if ok else '批准的本机代理端口离线'
    if observed['interfaces'] is None:
        return False, '网卡读取失败，无法确认隧道状态'
    if baseline['client'] == 'wireguard':
        from .wireguard import select_service
        pin = baseline['wireguard']
        state, row = select_service(observed.get('wireguard'), pin['service'])
        if state != 'healthy':
            notes = {'offline': '所选 WireGuard 隧道服务离线', 'missing': '所选 WireGuard 隧道服务已移除',
                     'permission': 'WireGuard 服务或所属进程被拒绝读取'}
            return False, notes.get(state, '所选 WireGuard 服务身份尚不能核实')
        if row['path'].casefold() != pin['path'].casefold() or row['sha256'] != pin['sha256']:
            return False, 'WireGuard 程序路径或文件摘要改变，请重新检测并审核守护基线'
        present = any(str(a.get('name', '')).casefold() == baseline['interface'].casefold() and a.get('up') is True for a in observed['interfaces'])
        return present, '所选 WireGuard 服务、程序摘要及对应网卡符合基线' if present else '所选 WireGuard 隧道网卡不在线'
    present = any(a.get('name') == baseline['interface'] and a.get('up') is True for a in observed['interfaces'])
    kernels = KERNELS[baseline['client']]
    client = not kernels or bool(set(kernels) & set(observed['clients']))
    return present and client, ('指定网卡与内核条件符合基线' if present and client else '指定隧道网卡不在线' if not present else '所选代理内核未运行')


class ProcessGuard:
    def __init__(self, store, home=None, io=None, scheduler=None, legacy_reader=None):
        self.store = store
        self.home = Path(home or Path.home()).resolve()
        self.root = store.root/'process-guard'
        self.data = StateStore(self.root, memory=store.memory)
        self.scheduler = scheduler or UserScheduler(self.home, self.root, role='guard')
        self.io = io or NativeGuardIO(self.home)
        self.legacy_reader = legacy_reader or getattr(self.io, 'legacy', None)
        self.memory, self.plans, self.mutexes = {}, {}, {}

    def legacy_conflict(self):
        from .component_inventory import blocking
        try: return blocking(self.legacy_reader()) if self.legacy_reader else True
        except (OSError, ValueError, TypeError, KeyError): return True

    def read(self, name, default):
        if self.data.memory:
            return self.memory.get(name, default)
        _safe_chain(self.root)
        data = _read(self.root/(name+'.private.json'))
        return load_object(data.decode('utf-8')) if data is not None else default

    def write(self, name, value):
        if self.data.memory:
            self.memory[name] = value
        else:
            _safe_chain(self.root)
            self.data._write(name+'.private.json', value)

    @contextmanager
    def lock(self, name='config'):
        if self.data.memory:
            mutex = self.mutexes.setdefault(name, threading.Lock())
            if not mutex.acquire(False):
                raise ValueError('进程守护正在执行，请稍后重试')
            try:
                yield
            finally:
                mutex.release()
            return
        _safe_chain(self.root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.root/('.'+name+'.lock')
        _safe_chain(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'r+b') as file:
            if not os.fstat(file.fileno()).st_size:
                file.write(b'0'); file.flush()
            file.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ValueError('进程守护正在执行，请稍后重试') from None
            try:
                yield
            finally:
                file.seek(0)
                if os.name == 'nt':
                    msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)

    def event(self, kind, note, **extra):
        value = {'at': utc_now(), 'kind': kind, 'text': note, **extra}
        if not self.data.memory:
            append_event(self.root/'events', value)
        previous = self.read('events', {}).get('rows', [])
        self.write('events', {'rows': (previous+[value])[-100:]})

    def config(self):
        value = self.read('config', {})
        if value:
            if (value.get('version') != 1 or type(value.get('enabled')) is not bool
                    or not isinstance(value.get('schedule'), dict) or not isinstance(value.get('settings_hash'), str)
                    or not isinstance(value.get('id'), str)):
                raise ValueError('进程守护方案损坏，请重新审核')
            command = value['schedule'].get('command')
            if command is not None and (not isinstance(command, list) or not command
                                       or not all(isinstance(item, str) and item for item in command)):
                raise ValueError('进程守护启动参数损坏，请重新审核')
            validate_baseline(value.get('baseline'))
        return value

    def options(self):
        snapshot = self.io.snapshot()
        if self.store.settings().get('client') == 'wireguard':
            from .wireguard import select_service
            state, row = select_service(snapshot.get('wireguard'), self.store.settings().get('wireguard_service', ''))
            return {'interfaces': [a['name'] for a in snapshot['interfaces'] or [] if state == 'healthy'
                                  and a['up'] and a['name'].casefold() == row['interface'].casefold()],
                    'reason': '仅列出本次 WireGuard 服务对应的在线网卡；找不到时先核对目标隧道并复检，不以其他 VPN 网卡替代。'}
        return {'interfaces': [a['name'] for a in snapshot['interfaces'] or [] if a['up']],
                'reason': '选择实际使用的隧道网卡；网卡在线只证明该组件状态，不证明全部流量接管。'}

    def current(self, report):
        settings = self.store.settings()
        return (settings.get('environment_confirmed') and SolutionPlans._current(report)
                and report.get('environment', {}).get('fingerprint') == fingerprint(settings)
                and any(f['id'] == 'target.region' and f['status'] == 'pass' for f in report.get('findings', [])))

    def prepare_from_report(self,report):
        """Use only the unique, measured target tunnel; never the first NIC."""
        interface=''
        if self.store.settings().get('connection_mode')=='tun':
            findings={f['id']:f for f in (report or {}).get('findings',[])}
            route=findings.get('target.tun_route',{})
            if route.get('status')!='pass':
                return {'state':'guided','reason':'先修复并复检目标 TUN 选路，再根据实际接口生成进程守护方案。'}
            inventory=next(iter(findings.get('system.inventory',{}).get('evidence',[])),{})
            adapters=inventory.get('network',{}).get('adapters',[])
            names=set()
            for row in route.get('evidence',[]):
                if row.get('error'):continue
                name=row.get('interface')
                if not name and type(row.get('interface_index')) is int:
                    matches=[a.get('Name',a.get('name')) for a in adapters if a.get('ifIndex')==row['interface_index']]
                    if len(matches)==1:name=matches[0]
                if not isinstance(name,str) or not name:
                    return {'state':'guided','reason':'目标选路没有可核对的接口名称，请在持续维护中手动选择已测量的隧道接口。'}
                names.add(name)
            if len(names)!=1:
                return {'state':'guided','reason':'本轮目标使用多个隧道或未取得唯一接口，请在持续维护中选择具体守护范围。'}
            interface=next(iter(names))
        return self.prepare(report,interface)

    def prepare(self, report, interface=''):
        if not self.current(report):
            return {'state': 'retest_required', 'reason': '先确认实际地区和桌面连接方式并检测，再生成守护方案。'}
        if self.legacy_conflict():
            return {'state': 'blocked', 'reason': '旧版进程守护仍存在或其归属未读明。先在持续维护中预览旧组件迁移，移除对应登记并复检，再启用原生守护。'}
        settings = self.store.settings()
        if settings['usage'] not in ('desktop', 'both') or settings['connection_mode'] not in ('tun', 'http_proxy'):
            return {'state': 'blocked', 'reason': '进程守护用于 Claude 桌面的 TUN 或本机 HTTP 代理连接；网页、Code 或直连不使用此功能。'}
        baseline = {'mode': settings['connection_mode'], 'proxy': settings['target_proxy'], 'client': settings['client'], 'interface': interface}
        snapshot = self.io.snapshot()
        if baseline['client'] == 'wireguard':
            from .wireguard import select_service
            state, row = select_service(snapshot.get('wireguard'), settings.get('wireguard_service', ''))
            if state != 'healthy':
                return {'state': 'blocked', 'reason': '先在目标设置选择并激活 WireGuard 隧道，完成服务身份专项检查，再生成守护方案。'}
            baseline['wireguard'] = {k: row[k] for k in ('service', 'path', 'sha256')}
        validate_baseline(baseline)
        good, note = health(baseline, snapshot, self.io)
        if not good or snapshot['unreadable']:
            return {'state': 'blocked', 'reason': note if not good else 'Claude 进程所属用户或路径无法读取，未启用自动停止。'}
        previous = self.config()
        state = self.scheduler.inspect(previous.get('schedule'))
        if state.get('present') is None or state.get('present') and not state.get('owned'):
            return {'state': 'blocked', 'reason': '同名守护任务冲突或归属无法确认，未覆盖。'}
        token = secrets.token_urlsafe(20)
        config = {'version': 1, 'policy_version': POLICY_VERSION, 'id': secrets.token_hex(16), 'enabled': False, 'baseline': baseline,
                  'settings_hash': fingerprint(settings), 'schedule': self.scheduler.build(5)}
        self.plans = {token: {'config': config, 'deadline': time.monotonic()+90, 'report_id': report['report_id']}}
        return {'state': 'planned', 'plan_id': token, 'effects': [
            '注册独立的当前用户进程守护，登录后运行；每 10 秒检查一次，关闭窗口后继续',
            '启用或更新方案时重启这一守护工作进程；替换期间监测会短暂中断，收到新心跳后才确认运行',
            '监测代理端口：'+baseline['proxy'] if baseline['mode'] == 'http_proxy' else '监测网卡：'+interface+'；客户端：'+baseline['client'],
            *(['固定隧道服务：'+baseline['wireguard']['service']+'；固定 WireGuard 程序摘要：'+baseline['wireguard']['sha256']+'；升级程序后需重新审核'] if baseline['client'] == 'wireguard' else []),
            '组件离线或监测失败时终止当前用户已识别的 Claude 桌面进程；未保存内容可能丢失',
            '核对安装路径、进程创建时间和所属用户；先尝试终止，2 秒仍未退出时强制终止，随后确认结果',
            '每次状态变化和停止操作写入本机日志；不切换账号、不重启 Claude、不修改网络',
            '10 秒轮询及停止过程存在流量窗口，不能替代防火墙；睡眠期间不运行，登录后由用户任务启动',
            '守护崩溃后系统最多等待 5 分钟再次调度；失去心跳时启动检查不再判定守护正常'],
            'reason': '请保存 Claude 中的工作，审核上述自动停止范围，再确认启用。'}

    def enable(self, token, report, confirmed=False):
        if confirmed is not True:
            return {'state': 'confirmation_required'}
        plan = self.plans.get(token) if isinstance(token, str) else None
        if not plan or time.monotonic() > plan['deadline'] or not self.current(report) or report['report_id'] != plan['report_id']:
            return {'state': 'retest_required', 'reason': '方案过期或检测变化，请重新生成。'}
        config = plan['config']
        if self.legacy_conflict():
            return {'state': 'retest_required', 'reason': '旧守护状态改变或未能读取，未启用新守护；先处理旧组件并复检。'}
        observed = self.io.snapshot()
        if config['settings_hash'] != fingerprint(self.store.settings()) or observed['unreadable'] or not health(config['baseline'], observed, self.io)[0]:
            return {'state': 'retest_required', 'reason': '连接或目标已变化，未启用旧方案。'}
        with self.lock():
            previous = self.config()
            self.write('config', config)
            try:
                self.scheduler.install(config['schedule'], previous.get('schedule'))
                self.event('approved', '已批准进程守护范围', baseline=config['baseline'])
                self.write('config', {**config, 'enabled': True})
                self.scheduler.start(config['schedule'])
            except (OSError, ValueError):
                self.write('config', config)
                self.event('start_failed', '任务启动未确认，守护保持停用；请核对任务权限。')
                return {'state': 'failed', 'reason': '任务启动未确认，尚未启用守护。请刷新状态并核对权限。'}
            self.plans.clear()
        return {'state': 'enabled', 'reason': '已批准并提交后台启动；需收到新心跳后才显示守护运行。'}

    def disable(self, confirmed=False):
        if confirmed is not True:
            return {'state': 'confirmation_required'}
        with self.lock():
            config = self.config()
            if config:
                self.write('config', {**config, 'enabled': False})
            try:
                self.scheduler.remove(config.get('schedule'))
                result = {'state': 'disabled', 'reason': '进程守护已停用，系统任务已移除；保留日志，不自动重开 Claude。'}
            except (OSError, ValueError):
                result = {'state': 'partial', 'reason': '自动停止已停用，系统任务移除尚未确认；保留记录供处理。'}
            self.event('disabled', result['reason'])
        return result

    def pulse(self):
        with self.lock():
            config = self.config()
            if not config.get('enabled'):
                return {'state': 'disabled'}
            previous = self.read('pulse', {})
            value = {'id': config['id'], 'policy_version': POLICY_VERSION, 'at': utc_now(), 'worker': self.io.identity()}
            if config.get('policy_version') != POLICY_VERSION:
                value.update(state='outdated', note='旧守护方案需要重新审核，未执行自动停止。')
            elif self.legacy_conflict():
                value.update(state='conflict', note='检测到旧守护登记或无法核实其状态，暂停原生自动停止；请处理旧组件并手动核对 Claude。')
            elif config['settings_hash'] != fingerprint(self.store.settings()):
                value.update(state='paused', note='目标改变，停止执行旧守护方案；请重新审核。')
            else:
                try:
                    snapshot = self.io.snapshot()
                    good, note = health(config['baseline'], snapshot, self.io)
                except (OSError, ValueError, RuntimeError):
                    # Re-read just the processes; if that also fails, no unknown
                    # target is killed and the heartbeat explicitly reports failure.
                    snapshot, good, note = None, False, '监测读取失败'
                if snapshot is None:
                    value.update(state='attention', note=note+'；未确认进程状态，需手动关闭 Claude。')
                elif good and not snapshot['unreadable']:
                    value.update(state='armed', note=note+'；进程守护轮询中。')
                else:
                    targets = snapshot['targets']
                    if snapshot['unreadable']:
                        note = '部分 Claude 进程身份无法核实'
                    if targets:
                        self.event('stop_requested', note+'，准备停止 Claude 桌面', count=len(targets))
                        try:
                            stopped = self.io.stop(targets) is True
                            after = self.io.snapshot()
                            stopped = stopped and not after['targets'] and not after['unreadable']
                        except (OSError, ValueError, RuntimeError):
                            stopped = False
                        self.event('stopped' if stopped else 'stop_failed', '已确认 Claude 桌面进程退出' if stopped else '未确认全部退出，请手动关闭 Claude')
                    else:
                        stopped = not snapshot['unreadable']
                    value.update(state='blocked' if stopped else 'attention', note=note+('；已确认没有受保护的桌面进程运行，恢复连接后请重新检测并打开。' if stopped else '；进程退出未确认，请手动关闭 Claude。'))
            if (previous.get('state'), previous.get('note')) != (value['state'], value['note']):
                self.event('state', value['note'], state=value['state'])
            self.write('pulse', value)
            return value

    def status(self):
        try:
            config = self.config()
            if not config:
                return {'state': 'disabled', 'enabled': False, 'events': [], 'reason': '尚未启用进程守护。'}
            pulse = self.read('pulse', {})
            schedule = self.scheduler.inspect(config['schedule'])
            elapsed = age(pulse.get('at'))
            live = (pulse.get('policy_version') == POLICY_VERSION and pulse.get('id') == config['id'] and elapsed is not None and 0 <= elapsed <= 30
                    and self.io.alive(pulse.get('worker', {}), config['schedule'].get('command', [''])[0]))
            outdated = (config.get('policy_version') != POLICY_VERSION or bool(pulse) and pulse.get('policy_version') != POLICY_VERSION or
                        getattr(self.scheduler, 'command', None) is not None and config['schedule'].get('command') != self.scheduler.command)
            state = ('disabled' if not config['enabled'] else 'paused' if config['settings_hash'] != fingerprint(self.store.settings())
                     else 'outdated' if outdated
                     else 'conflict' if self.legacy_conflict()
                     else 'schedule_unverified' if not schedule.get('registered') else pulse.get('state', 'waiting') if live else 'stale' if pulse else 'waiting')
            reasons = {'disabled': '进程守护已停用，保留日志。', 'paused': '目标已改变，请重新审核守护方案。',
                       'schedule_unverified': '后台任务注册或归属未确认，请检查任务状态。', 'stale': '守护心跳过期或工作进程已退出，请重新启用并复检。',
                       'outdated': '守护策略或软件目录已更新；请生成并批准新方案，等待新工作进程心跳。',
                       'conflict': '旧版守护存在或状态未核实，原生保护暂不能确认；请在旧组件迁移中处理。'}
            return {'state': state, 'enabled': config['enabled'], 'running': bool(live and schedule.get('registered') and state in ('armed', 'blocked')),
                    'scheduler': schedule, 'baseline': config['baseline'], 'heartbeat': pulse.get('at'),
                    'reason': reasons.get(state) or (pulse.get('note', '尚未收到有效的守护心跳。') if live else '等待新的后台心跳；旧记录不能证明进程守护仍在运行。'),
                    'events': self.read('events', {}).get('rows', [])[-20:], 'journal_path': str(self.root/'events')}
        except (OSError, ValueError, TypeError, KeyError):
            return {'state': 'invalid', 'enabled': False, 'running': False, 'events': [], 'reason': '进程守护记录无法验证，请手动检查并重新配置。'}

    def work(self, sleep=time.sleep):
        with self.lock('worker'):
            while True:
                started = time.monotonic()
                result = self.pulse()
                if result['state'] == 'disabled':
                    return 0
                sleep(max(0.1, INTERVAL-(time.monotonic()-started)))


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args == ['--check-runtime']:
        import psutil
        return 0 if psutil.__version__ else 3
    if args:
        return 3
    try:
        return ProcessGuard(StateStore()).work()
    except (OSError, ValueError, RuntimeError):
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
