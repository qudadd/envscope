"""Read-only identities for the fixed, separately installed legacy jobs.

Never imports or executes an installed script. A fixed name is a conflict until
its definition, principal, file ownership and script digest have been checked.
"""
import base64
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import xml.etree.ElementTree as ET

from .accounts import _safe_chain, AccountError
from .scheduler import NS

ROLES = {'guard': '旧版进程守护', 'timezone': '旧版时区守护',
         'update.system': '旧版系统更新任务', 'update.user': '旧版用户更新任务'}
LABELS = {'guard': 'local.claude-bodyguard', 'timezone': 'local.tz-watchdog',
          'update.system': 'local.claude-update', 'update.user': 'local.claude-update'}
SHA = re.compile('[a-f0-9]{64}\\Z')
LIMIT = 256 * 1024


def digest(data): return hashlib.sha256(data).hexdigest()


def read_regular(path, *, owner=None, limit=LIMIT):
    path = Path(path); _safe_chain(path)
    try: before = path.stat()
    except FileNotFoundError: return None
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
            or owner is not None and (before.st_uid != owner or before.st_mode & 0o022)):
        raise ValueError('组件文件类型、归属或权限不符合预期')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno()); data = stream.read(limit+1); after = os.fstat(stream.fileno())
    _safe_chain(path); final = path.stat()
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if len(data) > limit or len({key(s) for s in (before, opened, after, final)}) != 1:
        raise ValueError('组件文件在读取期间发生变化')
    return data


def error_code(error):
    return 'permission_denied' if isinstance(error, PermissionError) or getattr(error, 'winerror', None) == 5 else 'identity_unverified'


class Layout:
    def __init__(self, home, system=None, *, fixture=None):
        self.home = Path(home).resolve(); self.system = system or platform.system()
        self.fixture = fixture is not None
        self.root = Path(fixture['root']).resolve() if fixture else Path('/Library/PrivilegedHelperTools/io.qudadd.envscope.components')
        self.task = fixture['task'] if fixture else 'ClaudeBodyguard'
        self.labels = fixture['labels'] if fixture else LABELS.copy()
        self.daemons = Path(fixture['daemons']).resolve() if fixture else Path('/Library/LaunchDaemons')
        self.scripts = Path(fixture['scripts']).resolve() if fixture else Path('/Library/Application Support/claude-switcher')
        self.user_agents = self.home/'Library/LaunchAgents'

    def definition(self, role):
        return (self.user_agents if role == 'update.user' else self.daemons)/(self.labels[role]+'.plist')

    def script(self, role):
        if self.system == 'Windows': return self.home/'.claude-switcher/claude-bodyguard.ps1'
        if role == 'update.user': return self.home/'.local/bin/claude-switch.sh'
        return self.scripts/({'guard': 'claude-bodyguard.sh', 'timezone': 'tz-watchdog.sh'}.get(role, 'claude-switch.sh'))


def mac_definition(body, role, layout):
    value = plistlib.loads(body)
    allowed = {'Label', 'Program', 'ProgramArguments', 'RunAtLoad', 'StartInterval', 'Disabled',
               'StandardOutPath', 'StandardErrorPath', 'ProcessType', 'Nice', 'LowPriorityIO',
               'ThrottleInterval', 'ExitTimeOut', 'UserName'}
    if (not isinstance(value, dict) or set(value) - allowed or value.get('Label') != layout.labels[role]
            or value.get('Program') not in (None, '/bin/bash')
            or value.get('UserName') not in ((None,) if role == 'update.user' else (None, 'root'))):
        raise ValueError('任务定义包含未识别的字段或运行账户')
    args = ['/bin/bash', str(layout.script(role))] + (['update', '--auto'] if role.startswith('update.') else [])
    if value.get('ProgramArguments') != args:
        raise ValueError('任务命令不是已识别的固定脚本入口')
    if (type(value.get('StartInterval')) is not int or value['StartInterval'] <= 0
            or any(k in value and type(value[k]) is not bool for k in ('RunAtLoad', 'Disabled'))):
        raise ValueError('任务调度条件无法核实')
    return value


class MacJobs:
    """Apple's structured job dictionary, not a parser for launchctl print."""
    def __init__(self):
        self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sm = C.CDLL('/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement')
        P, I = C.c_void_p, C.c_long
        for name, args, result in (
            ('CFStringCreateWithCString', [P, C.c_char_p, C.c_uint32], P), ('CFRelease', [P], None),
            ('CFPropertyListCreateData', [P, P, I, C.c_ulong, C.POINTER(P)], P),
            ('CFDataGetLength', [P], I), ('CFDataGetBytePtr', [P], P)):
            fn = getattr(self.cf, name); fn.argtypes = args; fn.restype = result
        self.sm.SMJobCopyDictionary.argtypes = [P, P]; self.sm.SMJobCopyDictionary.restype = P
        self.domains = {False: P.in_dll(self.sm, 'kSMDomainSystemLaunchd').value,
                        True: P.in_dll(self.sm, 'kSMDomainUserLaunchd').value}

    def read(self, label, user=False):
        key = self.cf.CFStringCreateWithCString(None, label.encode(), 0x08000100)
        if not key: raise ValueError('服务标识读取失败')
        pointer = self.sm.SMJobCopyDictionary(self.domains[user], key)
        self.cf.CFRelease(key)
        if not pointer: return None
        error = C.c_void_p(); data = None
        try:
            data = self.cf.CFPropertyListCreateData(None, pointer, 100, 0, C.byref(error))
            if not data: raise ValueError('无法结构化读取已加载任务')
            size = self.cf.CFDataGetLength(data)
            if not 0 < size <= LIMIT: raise ValueError('已加载任务资料超出读取范围')
            value = plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data), size))
            if not isinstance(value, dict): raise ValueError('已加载任务资料无效')
            return value
        finally:
            if data: self.cf.CFRelease(data)
            if error.value: self.cf.CFRelease(error.value)
            self.cf.CFRelease(pointer)


def run_read(command, runner=subprocess.run):
    value = runner(command, capture_output=True, timeout=6,
                   env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'},
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    text = lambda v: v.decode('utf-8', errors='replace') if isinstance(v, bytes) else (v or '')
    if len(value.stdout or b'') + len(value.stderr or b'') > LIMIT: raise ValueError('任务读取结果过大')
    return value.returncode, text(value.stdout), text(value.stderr)


def mac_snapshot(layout, uid, *, jobs=None, runner=subprocess.run, roles=None):
    rows = []
    for role in roles or ROLES:
        row = {'id': role, 'title': ROLES[role], 'label': layout.labels[role], 'scope': 'user' if role == 'update.user' else 'system',
               'present': None, 'registered': None, 'owned': False, 'running': False, 'definition': None,
               'definition_sha': None, 'script_sha': None, 'enabled': None}
        try:
            path = layout.definition(role); owner = uid if role == 'update.user' else 0
            row['path'] = str(path); row['script'] = str(layout.script(role))
            body = read_regular(path, owner=owner)
            row['present'] = body is not None
            code, out, err = run_read(['/bin/launchctl', 'print', ('gui/'+str(uid) if role == 'update.user' else 'system')+'/'+layout.labels[role]], runner)
            if code and 'could not find service' not in (out+err).lower(): raise ValueError('服务登记读取失败')
            row['registered'] = code == 0
            if body is None:
                if row['registered']: raise ValueError('已加载任务没有可核对的原定义')
                row.update(owned=True, enabled=False); rows.append(row); continue
            value = mac_definition(body, role, layout)
            script = read_regular(layout.script(role), owner=owner, limit=1024*1024)
            if script is None: raise ValueError('任务脚本缺失，未将同名任务当作原版')
            row.update(definition=base64.b64encode(body).decode(), definition_sha=digest(body), script_sha=digest(script))
            info = path.stat(); row.update(mode=info.st_mode & 0o777, group=info.st_gid)
            if row['registered']:
                live = (jobs or MacJobs()).read(layout.labels[role], role == 'update.user')
                if not live or live.get('ProgramArguments') != value['ProgramArguments'] or live.get('Label') != value['Label']:
                    raise ValueError('已加载任务与磁盘定义不一致')
                row['running'] = type(live.get('PID')) is int and live['PID'] > 0
            row.update(owned=True, enabled=value.get('Disabled', False) is False)
        except (OSError, ValueError, TypeError, AccountError, subprocess.TimeoutExpired) as error:
            row['error'] = error_code(error); row['reason'] = str(error)[:180]
        rows.append(row)
    return {'format': 1, 'system': 'Darwin', 'actor': str(uid), 'rows': rows}


WINDOWS_READ = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\')
$task=$null
try{$task=$folder.GetTask(@TASK@)}catch{
 $e=$_.Exception;while($e.InnerException){$e=$e.InnerException}
 if(($e.HResult -band 0xffffffffL) -ne 0x80070002L){throw}
}
$actor=@ACTOR@
if(-not $task){@{present=$false;registered=$false;actor=$actor}|ConvertTo-Json -Compress;return}
$principal=$task.Definition.Principal
$sid=try{([Security.Principal.NTAccount]::new([string]$principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}catch{([Security.Principal.SecurityIdentifier]::new([string]$principal.UserId)).Value}
$sddl=[string]$task.GetSecurityDescriptor(7);$descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
$secure=$null -ne $descriptor.DiscretionaryAcl
foreach($ace in $descriptor.DiscretionaryAcl){if($ace.AceType -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -notin @($actor,'S-1-5-18','S-1-5-32-544') -and ($ace.AccessMask -band 0x500d0116)){$secure=$false}}
@{present=$true;registered=$true;actor=$actor;xml=[string]$task.Xml;sddl=$sddl;task_owner=$descriptor.Owner.Value;secure_acl=$secure;principal_sid=$sid;logon=[int]$principal.LogonType;level=[int]$principal.RunLevel;enabled=[bool]$task.Enabled;state=[int]$task.State;instances=[int]$task.GetInstances(0).Count}|ConvertTo-Json -Depth 8 -Compress
'''


def windows_definition(body, layout, *, parse_args):
    if isinstance(body, bytes): body = body.decode('utf-8-sig')
    tree = ET.fromstring(body)
    def at(path): return tree.find('/'.join('{'+NS+'}'+p for p in path.split('/')))
    actions, principals, triggers = at('Actions'), at('Principals'), at('Triggers')
    if (actions is None or len(actions) != 1 or actions[0].tag != '{'+NS+'}Exec'
            or principals is None or len(principals) != 1 or triggers is None or len(triggers) != 1
            or triggers[0].tag != '{'+NS+'}LogonTrigger'):
        raise ValueError('旧任务包含额外动作、账户或触发条件')
    program, arguments, cwd = at('Actions/Exec/Command'), at('Actions/Exec/Arguments'), at('Actions/Exec/WorkingDirectory')
    from .system_network_windows import powershell
    if (program is None or ((program.text or '').casefold() != 'powershell.exe' and (program.text or '').casefold() != powershell().casefold())
            or arguments is None or cwd is not None and (cwd.text or '').strip()):
        raise ValueError('旧任务程序或工作目录与识别范围不符')
    args = parse_args('powershell.exe '+arguments.text)
    expected = ['powershell.exe', '-noprofile', '-windowstyle', 'hidden', '-executionpolicy', 'bypass', '-file', str(layout.script('guard'))]
    if [s.casefold() for s in args] != [s.casefold() for s in expected]:
        raise ValueError('旧任务不是本用户的固定守护脚本')


def windows_snapshot(layout, sid=None, *, runner=subprocess.run, parse_args=None):
    from .system_network_windows import powershell, quote
    from .wireguard import WindowsServices
    row = {'id': 'guard', 'title': ROLES['guard'], 'label': layout.task, 'scope': 'user', 'present': None,
           'registered': None, 'owned': False, 'running': False, 'definition': None, 'definition_sha': None,
           'script_sha': None, 'enabled': None, 'script': str(layout.script('guard'))}
    try:
        code = WINDOWS_READ.replace('@TASK@', quote(layout.task)).replace('@ACTOR@', '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value')
        value = runner([powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', code],
                       capture_output=True, timeout=8, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if value.returncode or len(value.stdout) > LIMIT: raise ValueError('任务计划程序读取被拒绝或未完成')
        data = json.loads(value.stdout.decode('utf-8-sig') if isinstance(value.stdout, bytes) else value.stdout)
        if not isinstance(data.get('actor'), str) or not re.fullmatch('S-1-[0-9-]+', data['actor']): raise ValueError('当前用户身份读取失败')
        if sid is not None and sid != data['actor']: raise ValueError('当前用户身份改变')
        sid = data['actor']
        row.update(present=data.get('present'), registered=data.get('registered'))
        if row['present'] is False and row['registered'] is False:
            row.update(owned=True, enabled=False)
        else:
            if (row['present'] is not True or data.get('principal_sid') != sid or data.get('logon') != 3
                    or data.get('level') != 0 or data.get('task_owner') not in (sid, 'S-1-5-18', 'S-1-5-32-544')
                    or data.get('secure_acl') is not True or type(data.get('enabled')) is not bool
                    or data.get('state') not in (1, 3, 4) or type(data.get('instances')) is not int):
                raise ValueError('旧任务账户、权限或运行状态不在识别范围')
            raw = data['xml'].encode('utf-8'); windows_definition(raw, layout, parse_args=parse_args or WindowsServices().argv)
            source = read_regular(layout.script('guard'), limit=1024*1024)
            if source is None: raise ValueError('旧任务脚本缺失')
            row.update(owned=True, enabled=data['enabled'], running=data['state'] == 4 or data['instances'] > 0,
                       definition=base64.b64encode(raw).decode(), definition_sha=digest(raw), script_sha=digest(source),
                       security=data['sddl'], principal_sid=data['principal_sid'])
    except (OSError, ValueError, KeyError, TypeError, AccountError, subprocess.TimeoutExpired, ET.ParseError) as error:
        row['error'] = error_code(error); row['reason'] = str(error)[:180]
    return {'format': 1, 'system': 'Windows', 'actor': sid, 'rows': [row]}


def blocking(snapshot, role='guard'):
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('rows'), list): return True
    if any(not isinstance(r, dict) for r in snapshot['rows']): return True
    rows = [r for r in snapshot['rows'] if r.get('id') == role]
    return len(rows) != 1 or rows[0].get('owned') is not True or rows[0].get('present') is not False or rows[0].get('registered') is not False or bool(rows[0].get('error'))
