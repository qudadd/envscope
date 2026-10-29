"""Read-only Windows WireGuard service identity; never reads VPN key material.

SCM's own-process PID is checked against a held process handle and the exact
installed binary. A second SCM read and binary digest reject changes during
inspection. An arbitrary VPN NIC or a same-name process cannot satisfy this.
"""
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import time

from .accounts import _safe_chain, AccountError

PREFIX = 'WireGuardTunnel$'
MAX_SERVICES = 16
SCOPE = 'Windows 隧道服务、所属进程与对应网卡；不读取私钥，不验证握手或进程全流量。'


def valid_service(value, empty=False):
    return (isinstance(value, str) and (empty and value == '' or
            value.casefold().startswith(PREFIX.casefold()) and len(PREFIX) < len(value) <= 200
            and not any(c in '/\\' or ord(c) < 32 or ord(c) == 127 for c in value)))


def service_names():
    # EnumServicesStatusEx may silently omit services without QUERY_STATUS.
    # Enumerate the read-only registry names, then query each exact SCM record.
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services',
                        0, winreg.KEY_READ) as key:
        count = winreg.QueryInfoKey(key)[0]
        if count > 16384:
            raise ValueError('service inventory exceeds limit')
        names = [winreg.EnumKey(key, i) for i in range(count)]
    result = sorted(n for n in names if n.casefold().startswith(PREFIX.casefold()))
    if len(result) > MAX_SERVICES or any(not valid_service(n) for n in result):
        raise ValueError('tunnel service inventory exceeds limit')
    return result


def local_path(value):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        return False
    path = PureWindowsPath(value)
    return bool(path.is_absolute() and re.fullmatch(r'[A-Za-z]:\\', path.anchor)
                and '..' not in path.parts and not any(':' in p for p in path.parts[1:]))


def command_identity(args, service, binaries):
    if (not valid_service(service) or not isinstance(args, list) or len(args) != 3
            or args[1] != '/tunnelservice' or not all(local_path(p) for p in (args[0], args[2]))):
        raise ValueError('unrecognized-service-definition')
    binary = PureWindowsPath(args[0])
    if binary.name.casefold() != 'wireguard.exe' or binary not in {PureWindowsPath(p) for p in binaries}:
        raise ValueError('unrecognized-service-binary')
    config = PureWindowsPath(args[2]).name
    suffix = '.conf.dpapi' if config.casefold().endswith('.conf.dpapi') else '.conf'
    if not config.casefold().endswith(suffix) or config[:-len(suffix)].casefold() != service[len(PREFIX):].casefold():
        raise ValueError('service-config-name-mismatch')
    return str(binary)


def binary_digest(path, deadline):
    path = Path(path)
    _safe_chain(path)
    before = path.stat()
    if not path.is_file() or not 0 < before.st_size <= 64 * 1024**2:
        raise ValueError('service-binary-unavailable')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        identity = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024**2), b''):
            if time.monotonic() > deadline:
                raise TimeoutError('service-inspection-deadline')
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    _safe_chain(path)
    final = path.stat()
    # Some Windows Python runtimes expose different ctime semantics for stat
    # and fstat. Compare identity/size/mtime across APIs, ctime within each API.
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if (len({signature(s) for s in (before, identity, after, final)}) != 1
            or before.st_ctime_ns != final.st_ctime_ns or identity.st_ctime_ns != after.st_ctime_ns):
        raise ValueError('service-binary-changed')
    return digest.hexdigest()


class ServiceStatus(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in ('type', 'state', 'controls', 'exit', 'specific',
                                             'checkpoint', 'hint', 'pid', 'flags')]


class ServiceConfig(ctypes.Structure):
    _fields_ = [('type', wintypes.DWORD), ('start', wintypes.DWORD), ('error', wintypes.DWORD),
                ('command', wintypes.LPWSTR), ('group', wintypes.LPWSTR), ('tag', wintypes.DWORD),
                ('dependencies', wintypes.LPWSTR), ('account', wintypes.LPWSTR), ('display', wintypes.LPWSTR)]


class WindowsServices:
    """Only QUERY_CONFIG, QUERY_STATUS and PROCESS_QUERY_LIMITED_INFORMATION."""
    def __init__(self):
        self.adv = ctypes.WinDLL('advapi32', use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.shell = ctypes.WinDLL('shell32', use_last_error=True)
        ptr, dword, handle = ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE
        def bind(lib, name, args, result):
            fn = getattr(lib, name); fn.argtypes = args; fn.restype = result
        bind(self.adv, 'OpenSCManagerW', [wintypes.LPCWSTR, wintypes.LPCWSTR, dword], handle)
        bind(self.adv, 'OpenServiceW', [handle, wintypes.LPCWSTR, dword], handle)
        bind(self.adv, 'CloseServiceHandle', [handle], wintypes.BOOL)
        bind(self.adv, 'QueryServiceConfigW', [handle, ptr, dword, ctypes.POINTER(dword)], wintypes.BOOL)
        bind(self.adv, 'QueryServiceStatusEx', [handle, ctypes.c_int, ptr, dword, ctypes.POINTER(dword)], wintypes.BOOL)
        bind(self.shell, 'CommandLineToArgvW', [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)], ctypes.POINTER(wintypes.LPWSTR))
        bind(self.kernel, 'LocalFree', [ptr], ptr)
        bind(self.kernel, 'OpenProcess', [dword, wintypes.BOOL, dword], handle)
        bind(self.kernel, 'CloseHandle', [handle], wintypes.BOOL)
        bind(self.kernel, 'QueryFullProcessImageNameW', [handle, dword, wintypes.LPWSTR, ctypes.POINTER(dword)], wintypes.BOOL)
        bind(self.kernel, 'GetProcessTimes', [handle, *([ctypes.POINTER(wintypes.FILETIME)] * 4)], wintypes.BOOL)

    @staticmethod
    def check(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def read(self, service):
        scm = self.check(self.adv.OpenSCManagerW(None, None, 1))
        handle = None
        try:
            handle = self.check(self.adv.OpenServiceW(scm, service, 1 | 4))
            size = wintypes.DWORD()
            self.adv.QueryServiceConfigW(handle, None, 0, ctypes.byref(size))
            if not 0 < size.value <= 65536:
                self.check(False)
            data = ctypes.create_string_buffer(size.value)
            self.check(self.adv.QueryServiceConfigW(handle, data, len(data), ctypes.byref(size)))
            config = ctypes.cast(data, ctypes.POINTER(ServiceConfig)).contents
            status = ServiceStatus()
            self.check(self.adv.QueryServiceStatusEx(handle, 0, ctypes.byref(status), ctypes.sizeof(status), ctypes.byref(size)))
            return {'type': config.type, 'start': config.start, 'account': config.account,
                    'command': config.command, 'status_type': status.type, 'state': status.state, 'pid': status.pid}
        finally:
            if handle: self.adv.CloseServiceHandle(handle)
            self.adv.CloseServiceHandle(scm)

    def argv(self, command):
        if not isinstance(command, str) or len(command) > 32768 or '\x00' in command:
            raise ValueError('invalid-service-command')
        count = ctypes.c_int()
        args = self.check(self.shell.CommandLineToArgvW(command, ctypes.byref(count)))
        try:
            if not 0 < count.value <= 16: raise ValueError('invalid-service-command')
            return [args[i] for i in range(count.value)]
        finally:
            self.kernel.LocalFree(ctypes.cast(args, ctypes.c_void_p))

    def process(self, pid):
        handle = self.check(self.kernel.OpenProcess(0x1000, False, pid))
        try:
            size = wintypes.DWORD(32768); image = ctypes.create_unicode_buffer(size.value)
            self.check(self.kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)))
            times = [wintypes.FILETIME() for _ in range(4)]
            self.check(self.kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)))
            return {'path': image.value, 'created': (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime,
                    'exited': bool(times[1].dwHighDateTime or times[1].dwLowDateTime)}
        finally:
            self.kernel.CloseHandle(handle)


class WireGuardReader:
    def __init__(self, system=None, names=None, api=None, binaries=None, digest=None):
        self.system = system or platform.system()
        self.names, self.api = names or service_names, api
        self.binaries = binaries if binaries is not None else [str(Path(root)/'WireGuard/wireguard.exe')
            for root in {os.environ.get('ProgramFiles', 'C:/Program Files'),
                         os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')}]
        self.digest = digest or binary_digest

    def collect(self):
        result = {'platform': self.system, 'complete': False, 'services': [], 'scope': SCOPE}
        if self.system != 'Windows':
            return {**result, 'error': 'unsupported'}
        deadline = time.monotonic() + 4
        try:
            names = self.names()
            if (not isinstance(names, list) or len(names) > MAX_SERVICES or any(not valid_service(n) for n in names)
                    or len({n.casefold() for n in names}) != len(names)):
                raise ValueError('invalid-service-inventory')
            api = self.api or WindowsServices()
            for name in names:
                row = {'service': name, 'tunnel': name[len(PREFIX):], 'verified': False}
                try:
                    if time.monotonic() > deadline: raise TimeoutError()
                    config = api.read(name)
                    row['state'] = {1: 'stopped', 4: 'running', 7: 'paused'}.get(config['state'], 'transitioning')
                    binary = command_identity(api.argv(config['command']), name, self.binaries)
                    if (config['type'] != 0x10 or config['status_type'] != 0x10
                            or (config.get('account') or '').casefold() not in ('localsystem', 'nt authority\\system')):
                        raise ValueError('service-identity-mismatch')
                    sha = self.digest(binary, deadline)
                    row.update(path=binary, sha256=sha)
                    if config['state'] != 4:
                        if config != api.read(name): raise ValueError('service-changed-during-inspection')
                        continue
                    if type(config.get('pid')) is not int or config['pid'] <= 0:
                        raise ValueError('service-pid-unavailable')
                    process = api.process(config['pid'])
                    if (not local_path(process['path']) or PureWindowsPath(process['path']) != PureWindowsPath(binary)
                            or type(process.get('created')) is not int or process['created'] <= 0 or process.get('exited') is not False):
                        raise ValueError('service-process-mismatch')
                    # Check both ends again. PID reuse, service restart, program
                    # replacement or altered configuration invalidate this sample.
                    if (config != api.read(name) or process != api.process(config['pid'])
                            or sha != self.digest(binary, deadline)):
                        raise ValueError('service-changed-during-inspection')
                    row.update(verified=True, pid=config['pid'], created=process['created'], interface=row['tunnel'])
                except OSError as error:
                    row['error'] = 'permission_denied' if isinstance(error, PermissionError) or getattr(error, 'winerror', None) == 5 else 'service-read-unavailable'
                except AccountError:
                    row['error'] = 'unsafe-service-path'
                except (ValueError, KeyError, TypeError) as error:
                    row['error'] = str(error) if isinstance(error, ValueError) else 'malformed-service-record'
                finally:
                    result['services'].append(row)
            result['complete'] = time.monotonic() <= deadline
            if not result['complete']: result['error'] = 'service-inspection-deadline'
        except OSError as error:
            result['error'] = 'permission_denied' if isinstance(error, PermissionError) or getattr(error, 'winerror', None) == 5 else 'service-inventory-unavailable'
        except (ValueError, TypeError):
            result['error'] = 'invalid-service-inventory'
        return result


def select_service(observed, service=''):
    """Do not guess between several tunnels, even if only one happens to be up."""
    if not valid_service(service, empty=True) or not isinstance(observed, dict):
        return 'unknown', None
    if observed.get('platform') != 'Windows': return 'unsupported', None
    rows = observed.get('services', [])
    if not isinstance(rows, list) or any(not isinstance(r, dict) or not valid_service(r.get('service')) for r in rows):
        return 'unknown', None
    if service:
        rows = [r for r in rows if r['service'].casefold() == service.casefold()]
    elif len(rows) > 1:
        return 'ambiguous', None
    if len(rows) != 1:
        return ('missing' if not rows and observed.get('complete') is True else 'unknown'), None
    row = rows[0]
    if row.get('error') == 'permission_denied': return 'permission', row
    if row.get('error'): return 'unknown', row
    if observed.get('complete') is not True: return 'unknown', row
    if row.get('state') in ('stopped', 'paused'): return 'offline', row
    if (row.get('verified') is True and row.get('state') == 'running' and row.get('interface') == row['service'][len(PREFIX):]
            and local_path(row.get('path')) and PureWindowsPath(row['path']).name.casefold() == 'wireguard.exe'
            and re.fullmatch('[a-f0-9]{64}', str(row.get('sha256', '')))
            and type(row.get('pid')) is int and row['pid'] > 0 and type(row.get('created')) is int and row['created'] > 0):
        return 'healthy', row
    return 'unknown', row


def finding(observed, service=''):
    from .model import Finding, Status
    state, row = select_service(observed, service)
    messages = {'healthy': '所选 WireGuard 隧道服务及所属进程已核对', 'offline': '所选 WireGuard 隧道服务未运行',
        'missing': '未找到所选 WireGuard 隧道服务', 'ambiguous': '发现多个 WireGuard 隧道，请选择本次使用的一个',
        'permission': '系统拒绝读取所选 WireGuard 服务或进程', 'unsupported': '此专项检查仅适用于 Windows 官方 WireGuard 隧道服务',
        'unknown': 'WireGuard 服务身份或读取结果尚不能确认'}
    status = Status.PASS if state == 'healthy' else Status.FAIL if state in ('offline', 'missing') else Status.UNKNOWN
    return Finding('target.wireguard', 'WireGuard 隧道服务', status, messages[state], 'windows-wireguard-service',
                   [row or {'error': observed.get('error') if isinstance(observed, dict) else 'unavailable', 'state': state}],
                   [SCOPE, '未验证数字签名；安装位置与当前文件摘要用于核对并固定本次基线。'],
                   '在目标设置选择具体隧道；在 WireGuard 官方客户端激活该隧道，再复检。权限拒绝时用服务管理器核对读取权限；不要上传或粘贴 VPN 私钥。')
