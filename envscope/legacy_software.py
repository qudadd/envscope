"""Reviewed, reversible removal of fixed legacy program paths, never accounts.

Installed files are read as data. They are never imported or executed. Each
same-volume move preserves the original file, ACLs, xattrs and inode; unknown
items and conflicting destinations are retained for manual review.
"""
from contextlib import nullcontext
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import stat
import subprocess
import time

import psutil

from .accounts import AccountError, _safe_chain
from .browser_sessions import _read, _write
from .component_inventory import read_regular
from .event_log import append_event
from .legacy_components import key, retirable
from .remedies import ConfigRemedies
from .snapshot_archive import restrict_private_directory

TOKEN = re.compile(r'[a-f0-9]{32}\Z')
PENDING = {'prepared', 'retiring_jobs', 'moving', 'restoring', 'partial'}
STATES = PENDING | {'committed', 'restored'}
LIMIT = 256*1024*1024


def layout(home, system):
    home = Path(home)
    if system == 'Windows':
        return {'core': home/'.claude-switcher/claude-switch.ps1',
                'ui': home/'.claude-switcher/SwitcherUI.ps1',
                'guard': home/'.claude-switcher/claude-bodyguard.ps1',
                'shortcut': home/'Desktop/Claude切换器.lnk'}
    if system != 'Darwin': return {}
    paths = {'core': home/'.local/bin/claude-switch.sh',
             'core.backup': home/'.local/bin/claude-switch.sh.bak',
             'guard': home/'.local/bin/claude-bodyguard.sh',
             'guard.backup': home/'.local/bin/claude-bodyguard.sh.bak',
             'timezone': home/'.local/bin/tz-watchdog.sh',
             'timezone.backup': home/'.local/bin/tz-watchdog.sh.bak',
             'stun': home/'.claude-switcher/stun-probe.py',
             'app': home/'Desktop/Claude切换器.app'}
    for role, label in (('guard','claude-bodyguard'),('timezone','tz-watchdog'),('update','claude-update')):
        paths['template.'+role] = home/('.local/bin/local.'+label+'.plist')
    return paths


def rename_exclusive(source, destination):
    """An existing destination is evidence, never an overwrite target."""
    source, destination = Path(source), Path(destination)
    _safe_chain(source); _safe_chain(destination)
    if os.name == 'nt':
        os.rename(source, destination)
        return
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib' if platform.system()=='Darwin' else None, use_errno=True)
    if platform.system()=='Darwin':
        move = library.renameatx_np
        flag = 4  # RENAME_EXCL
    else:
        move = library.renameat2
        flag = 1  # RENAME_NOREPLACE, used only by Linux fixtures.
    move.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    move.restype = ctypes.c_int
    if move(-2 if platform.system()=='Darwin' else -100, os.fsencode(source),
            -2 if platform.system()=='Darwin' else -100, os.fsencode(destination), flag):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def windows_security(path):
    """Read owner/group/DACL for change detection; never log the descriptor."""
    from ctypes import wintypes
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    get=api.GetNamedSecurityInfoW
    get.argtypes=[wintypes.LPWSTR,ctypes.c_int,wintypes.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    get.restype=wintypes.DWORD
    convert=api.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes=[ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.LPWSTR),ctypes.c_void_p]
    convert.restype=wintypes.BOOL
    free=kernel.LocalFree;free.argtypes=[ctypes.c_void_p];free.restype=ctypes.c_void_p
    descriptor=ctypes.c_void_p();string=wintypes.LPWSTR()
    code=get(str(path),1,7,None,None,None,None,ctypes.byref(descriptor))
    if code:raise ctypes.WinError(code)
    try:
        if not convert(descriptor,1,7,ctypes.byref(string),None):raise ctypes.WinError(ctypes.get_last_error())
        return string.value.encode('utf-8')
    finally:
        if string:free(ctypes.cast(string,ctypes.c_void_p))
        free(descriptor)


def security_comparison(value):
    # A same-volume move can convert inherited ACEs to identical explicit
    # rights. Compare the effective descriptor here; retain the original SDDL
    # separately so restoration also recovers inheritance behavior.
    value=re.sub(r'D:(?:P|AI|AR)*','D:',value.decode('utf-8'),count=1)
    return re.sub(r'\(([^;()]+);([^;()]*);',lambda m:'('+m[1]+';'+m[2].replace('ID','')+';',value).encode('utf-8')


def restore_windows_security(path,value):
    from ctypes import wintypes
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    convert=api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p];convert.restype=wintypes.BOOL
    set_security=api.SetFileSecurityW;set_security.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.c_void_p];set_security.restype=wintypes.BOOL
    free=kernel.LocalFree;free.argtypes=[ctypes.c_void_p];free.restype=ctypes.c_void_p
    descriptor=ctypes.c_void_p()
    if not convert(value,1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
    try:
        flags=4|(0x80000000 if re.search(r'D:(?:AI|AR)*P',value) else 0x20000000)
        if not set_security(str(path),flags,descriptor):raise ctypes.WinError(ctypes.get_last_error())
    finally:free(descriptor)


def signature(path):
    """Bounded tree digest without following links; no contents enter journals."""
    path = Path(path); _safe_chain(path)
    if not os.path.lexists(path): return None
    digest = hashlib.sha256(); total = count = actual_bytes = 0; todo = [path]
    while todo:
        current = todo.pop(); _safe_chain(current); before = current.lstat()
        if getattr(before,'st_file_attributes',0)&0x400 or stat.S_ISLNK(before.st_mode):
            raise ValueError('程序路径包含链接或重解析点，资料保留')
        if os.name != 'nt' and (before.st_uid != os.getuid() or before.st_mode&0o022):
            raise ValueError('程序归属或可写权限无法核实，请由原用户处理')
        count += 1
        if count > 4096: raise ValueError('程序目录超过 4096 项，请手动核对')
        relative = '.' if current==path else current.relative_to(path).as_posix()
        digest.update(json.dumps([relative,stat.S_IMODE(before.st_mode),before.st_uid,before.st_gid],ensure_ascii=True).encode())
        if os.name=='nt':digest.update(security_comparison(windows_security(current)))
        if stat.S_ISDIR(before.st_mode):
            digest.update(b'D'); todo.extend(sorted(current.iterdir(), reverse=True)); continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('程序含共享文件或特殊文件，资料保留')
        total += before.st_size
        if total > LIMIT: raise ValueError('程序大小超过 256 MiB，请手动核对')
        digest.update(b'F')
        fd = os.open(current,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
        with os.fdopen(fd,'rb') as stream:
            opened = os.fstat(stream.fileno())
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                actual_bytes+=len(chunk)
                if actual_bytes>LIMIT:raise ValueError('读取期间程序超过大小限制，资料保留')
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        fingerprint = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
        if len({fingerprint(s) for s in (before,opened,after,current.lstat())}) != 1:
            raise ValueError('程序在读取时发生变化，请重新预览')
    return {'sha256':digest.hexdigest(),'bytes':total,'entries':count}


def recognized(path, role, system, home):
    if role=='app':
        body = read_regular(path/'Contents/Info.plist')
        value = plistlib.loads(body or b'')
        return (value.get('CFBundleIdentifier')=='local.claude-switcher'
                and value.get('CFBundleExecutable')=='ClaudeSwitcher'
                and (path/'Contents/MacOS/ClaudeSwitcher').is_file())
    if role=='shortcut':
        # IShellLinkW/IPersistFile use UTF-16 regardless of the system ANSI
        # codepage. Resolve/Save/Run are never invoked by this read path.
        from .windows_shortcut import read_shortcut
        value=read_shortcut(path)
        from .wireguard import WindowsServices
        args = WindowsServices().argv('powershell.exe '+value.get('args',''))[1:]
        target = Path(value.get('target','')).name.casefold()
        return (target in ('powershell.exe','pwsh.exe') and len(args)==7
                and [a.casefold() for a in args[:6]]==['-noprofile','-windowstyle','hidden','-executionpolicy','bypass','-file']
                and os.path.normcase(args[6])==os.path.normcase(str(Path(home)/'.claude-switcher/SwitcherUI.ps1')))
    body = read_regular(path,limit=2*1024*1024)
    if body is None: return False
    text = body.decode('utf-8-sig',errors='replace')
    if role.startswith('template.'):
        value = plistlib.loads(body)
        label = {'guard':'local.claude-bodyguard','timezone':'local.tz-watchdog','update':'local.claude-update'}[role.split('.')[1]]
        return value.get('Label')==label and isinstance(value.get('ProgramArguments'),list)
    base = role.split('.')[0]
    checks = {'core': ('claude-switch','checkdetail'), 'ui':('claude-switcher','Window'),
              'guard': ('Claude','PROXY_MODE' if system=='Windows' else 'claude-bodyguard.log'),
              'timezone':('tz-watchdog.log','settimezone'), 'stun':('stun_public_ip','Binding')}
    return all(marker in text for marker in checks.get(base, ('\x00never',)))


def process_state(paths):
    """Read-only known interpreter / application scan; unknown is not stopped."""
    needles = [os.path.normcase(str(p)).casefold() for p in paths]
    interpreters = {'powershell','powershell.exe','pwsh','pwsh.exe','bash','sh','zsh','python','python.exe','python3','claudeswitcher'}
    unknown = False
    for process in psutil.process_iter(['name']):
        try:
            if process.pid==os.getpid(): continue
            name = (process.info.get('name') or '').casefold()
            if name not in interpreters: continue
            args = process.cmdline()
            if not args: unknown=True; continue
            joined = '\n'.join(os.path.normcase(a).casefold() for a in args)
            if any(p in joined for p in needles): return True
            # Relative invocations still refer to the same reviewed file.
            for argument in args[1:]:
                if any(Path(argument).name.casefold()==p.name.casefold() for p in paths):
                    if any(os.path.normcase(str(Path(process.cwd())/argument)).casefold()==p for p in needles): return True
        except psutil.NoSuchProcess: continue
        except (psutil.Error,OSError): unknown=True
    return None if unknown else False


class NoSystemFiles:
    fixture = True
    def snapshot(self): return []
    def status(self): return {'id':'','state':'not_configured'}
    def execute(self,*args): raise ValueError('隔离测试不执行系统程序清理')


class MacSystemFiles:
    def __init__(self, components): self.components=components; self.fixture=components.fixture
    def snapshot(self):
        rows=[]
        for role,filename in (('guard','claude-bodyguard.sh'),('timezone','tz-watchdog.sh'),('core','claude-switch.sh')):
            path=self.components.layout.scripts/filename
            row={'id':'system.'+role,'path':str(path),'present':None,'eligible':False,'scope':'system'}
            try:
                raw=read_regular(path,owner=0,limit=2*1024*1024)
                row['present']=raw is not None
                if raw is not None:
                    info=path.stat()
                    # Recognition is a fixed legacy location plus program markers,
                    # not a claim of upstream code signing or trustworthiness.
                    markers={'guard':(b'Claude',b'claude-bodyguard.log'),'timezone':(b'tz-watchdog.log',b'settimezone'),'core':(b'claude-switch',b'checkdetail')}[role]
                    row.update(sha256=hashlib.sha256(raw).hexdigest(),mode=stat.S_IMODE(info.st_mode),group=info.st_gid,
                               eligible=all(m in raw for m in markers))
                    if not row['eligible']: row['reason']='固定路径内的程序内容未识别，请管理员手动核对'
            except (OSError,ValueError,AccountError): row['reason']='系统文件归属、权限或内容无法读取，请管理员核对；未执行清理'
            rows.append(row)
        return rows
    def status(self):
        root=self.components.layout.root;_safe_chain(root)
        if root.exists():
            info=root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('系统恢复目录归属或权限无法核实')
        raw=read_regular(root/'software-latest.plist',owner=0,limit=1024*1024)
        if raw is None:return {'id':'','state':'not_configured'}
        value=plistlib.loads(raw)
        if (not isinstance(value,dict) or type(value.get('format')) is not int or value['format']!=1 or value.get('fixture') is not self.fixture or not TOKEN.fullmatch(str(value.get('id','')))
                or value.get('state') not in STATES):raise ValueError('系统程序恢复记录无法核实')
        return value
    def execute(self,action,payload):return self.components.execute(action+'-files',payload)


class SoftwareCleanup:
    def __init__(self,home,components,*,system=None,root=None,processes=None,system_files=None,
                 pending=None,transaction_lock=None,clock=time.monotonic,recognizer=None):
        self.home=Path(home).resolve();self.system=system or platform.system();self.paths=layout(self.home,self.system)
        self.components=components;self.root=Path(root or self.home/'.envscope/legacy-software')
        self.locker=ConfigRemedies(self.root,self.root);self.locker.backups=self.root
        self.system_files=system_files or NoSystemFiles();self.processes=processes or process_state
        self.pending=pending or (lambda:[]);self.transaction_lock=transaction_lock or nullcontext
        self.clock=clock;self.plans={};self.recognizer=recognizer or recognized;self.cached=None

    def _record(self):
        index=self.root/'latest.private.json'
        if not os.path.lexists(index): return None
        value=_read(index)
        if (not isinstance(value,dict) or set(value)!={'format','id','state','rows','system_record','system_rows','at'} or type(value.get('format')) is not int or value['format']!=1
                or not TOKEN.fullmatch(str(value.get('id',''))) or value.get('state') not in STATES
                or not isinstance(value.get('rows'),list) or not isinstance(value.get('system_record'),str)
                or value['system_record'] and not TOKEN.fullmatch(value['system_record'])
                or not isinstance(value.get('system_rows'),list)):
            raise ValueError('程序清理恢复记录无效，保留现场，请手动核对')
        ids=[]
        for row in value['rows']:
            if (not isinstance(row,dict) or set(row)!={'id','signature','security'} or row['id'] not in self.paths or row['id'] in ids
                    or not isinstance(row['security'],str) or len(row['security'])>2048
                    or not isinstance(row['signature'],dict) or not re.fullmatch('[a-f0-9]{64}',str(row['signature'].get('sha256','')))):
                raise ValueError('程序恢复范围无法核实，未根据记录中的路径执行操作')
            ids.append(row['id'])
        system_ids=[]
        for row in value['system_rows']:
            if (not isinstance(row,dict) or row.get('id') not in ('system.guard','system.timezone','system.core') or row['id'] in system_ids
                    or not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256','')))
                    or type(row.get('mode')) is not int or type(row.get('group')) is not int):
                raise ValueError('系统程序原值无法核实，未恢复')
            system_ids.append(row['id'])
        if bool(system_ids)!=bool(value['system_record']):raise ValueError('系统恢复范围不完整')
        return value

    def _save(self,record,state):
        if len(json.dumps({**record,'state':state},separators=(',',':')).encode('utf-8'))>8000:
            raise ValueError('恢复记录超过安全读取大小，未移动程序，请分批手动核对')
        _safe_chain(self.root);self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        restrict_private_directory(self.root)
        record.update(state=state,at=time.time())
        _write(self.root/'latest.private.json',record)
        append_event(self.root/'events',{'at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'kind':state,
                                       'transaction':record['id'],'text':'旧程序清理阶段：'+state})

    def _backup(self,path,ident,role):return path.parent/('.envscope-legacy-'+ident)/role

    def _rows(self):
        rows=[]
        for role,path in self.paths.items():
            row={'id':role,'path':str(path),'present':None,'eligible':False,'scope':'user'}
            try:
                value=signature(path);row['present']=value is not None
                if value:
                    row['signature']=value;row['eligible']=self.recognizer(path,role,self.system,self.home) is True
                    if not row['eligible']:row['reason']='固定路径内的内容未识别，请手动核对，未移动'
            except (OSError,ValueError,AccountError,plistlib.InvalidFileException):
                row['reason']='程序类型、归属或权限无法核实，请由原用户核对，未移动'
            rows.append(row)
        return rows+self.system_files.snapshot()

    def status(self):
        try:
            record=self._record();rows=self._rows()
            self.cached={'state':record['state'] if record else 'not_configured','rows':rows,
                    'can_restore':bool(record and record['state']!='restored'),'needs_recovery':bool(record and record['state'] in PENDING),
                    'reason':'仅处理所列旧程序与启动入口；账号、凭据、配置、日志保留。存档可恢复；恢复程序不自动恢复后台任务。'}
        except (OSError,ValueError,AccountError):
            self.cached={'state':'invalid','rows':[],'can_restore':False,'reason':'清理记录无法读取，现场已保留，请由原用户手动核对。'}
        return self.cached

    def peek(self):
        return self.cached or {'state':'not_checked','rows':[],'can_restore':False,'reason':'进入持续维护后读取旧程序清单；只读核对不会移除文件。'}

    def _jobs(self):
        value=self.components._snapshot()
        for row in value['rows']:
            if row.get('error') or row.get('owned') is not True or type(row.get('present')) is not bool or type(row.get('registered')) is not bool:
                raise ValueError('有旧后台任务无法核实；先在“旧后台任务迁移”处理标红项目')
        return value

    def _quiet(self,jobs=None,*,allow_managed=False):
        if self.pending():raise ValueError('账号事务尚未完成；先使用账号恢复入口，未移动程序')
        ignored={os.path.normcase(str(r['script'])) for r in (jobs or {}).get('rows',[])
                 if allow_managed and retirable(r) and isinstance(r.get('script'),str)}
        paths=list(self.paths.values())+[Path(r['path']) for r in self.system_files.snapshot()]
        state=self.processes([p for p in paths if os.path.normcase(str(p)) not in ignored])
        if state is not False:
            raise ValueError('旧界面或手动脚本仍在运行，或进程权限不足；请退出旧界面及脚本，必要时由原用户或管理员核对，再重新预览')

    def prepare(self,roles=None,*,restore=False):
        if type(restore) is not bool:raise ValueError('恢复选项需要明确的布尔值')
        try:
            record=self._record();jobs=self._jobs();self._quiet(jobs,allow_managed=True);system_record=self.system_files.status()
            rows=self._rows();byid={r['id']:r for r in rows};job_plan=None
            if restore:
                if not record or record['state']=='restored':return {'state':'not_needed','reason':'没有待恢复的程序清理记录'}
                selected=[r['id'] for r in record['rows']]
                selected += [r['id'] for r in record['system_rows']]
                if roles is not None and roles!=selected:raise ValueError('恢复以原事务的全部程序为范围，请勿混入其他项目')
                effects=['按原事务恢复旧程序及启动入口，核对存档摘要；新出现或改变的文件不覆盖',
                         '后台任务保持停用；恢复后如需旧任务，请另行预览“恢复原任务”，该操作可能立即运行旧脚本',
                         '所有账号、凭据、系统地区、代理配置均保留；不自动启动旧界面或 Claude']
            else:
                if record and record['state']!='restored':return {'state':'guided','reason':'已有程序清理存档，请先恢复或手动核对，不覆盖上笔恢复记录'}
                selected=roles if roles is not None else [r['id'] for r in rows if r['eligible']]
                if (not isinstance(selected,list) or len(selected)>20
                        or any(not isinstance(r,str) or r not in byid for r in selected)
                        or len(set(selected))!=len(selected)):raise ValueError('请选择清单内的程序项目')
                if not selected:return {'state':'not_needed','reason':'没有可自动清理的旧程序；无法识别的项目请按红色说明手动核对'}
                if any(byid[r].get('eligible') is not True for r in selected):raise ValueError('所选程序未通过内容与权限核对，未执行清理')
                if any(r.startswith('system.') for r in selected) and system_record.get('state') not in ('not_configured','restored'):
                    raise ValueError('系统程序已有未恢复的清理事务，请先核对原事务，未覆盖它')
                targets=[r['id'] for r in jobs['rows'] if r.get('present') or r.get('registered')]
                if targets:
                    if any(not retirable(r) for r in jobs['rows'] if r['id'] in targets):raise ValueError('旧任务无法安全停用，请先手动核对')
                    job_plan=self.components.prepare(targets)
                    if job_plan.get('state')!='planned':raise ValueError(job_plan.get('reason','旧任务迁移需要先处理恢复记录'))
                effects=['先停用并独立读回已识别的旧后台任务，再逐项移走所选程序；失败时停止并保留恢复记录',
                         '清理范围：'+'、'.join(str(byid[r]['path']) for r in selected),
                         '文件移入同目录下受限的 .envscope-legacy-事务号 存档，保留原权限、属性和摘要；不是永久删除',
                         '账号卷、OAuth 凭据、Device Fingerprint、当前状态及 keepdata 均保留；系统地区、代理规则和配置不改写',
                         '清理后自动复检；旧任务停用后有保护间隔，需要另行审核 EnvScope 守护']
                if job_plan:effects+=job_plan.get('effects',[])
            token=secrets.token_urlsafe(24)
            self.plans={token:{'deadline':self.clock()+90,'id':secrets.token_hex(16),'selected':selected,'restore':restore,
                               'record':record,'rows':rows,'jobs':jobs,'system_record':system_record,'job_plan':job_plan}}
            return {'state':'planned','plan_id':token,'roles':selected,'effects':effects,'reason':'审核所列影响后确认；需要系统权限时由系统申请本次授权。'}
        except (OSError,ValueError,AccountError) as error:return {'state':'guided','reason':str(error)[:280]}

    def apply(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if not plan or self.clock()>plan['deadline']:return {'state':'retest_required','reason':'方案已过期，请重新预览'}
        record=None
        try:
            with self.locker._lock():
                self._quiet(plan['jobs'],allow_managed=True)
                if key(self._record())!=key(plan['record']) or key(self._rows())!=key(plan['rows']) or key(self._jobs())!=key(plan['jobs']) or key(self.system_files.status())!=key(plan['system_record']):
                    return {'state':'retest_required','reason':'程序、任务或恢复记录已改变，未执行旧方案'}
                if self.clock()>plan['deadline']:return {'state':'retest_required','reason':'核对期间方案已过期，请重新预览'}
                record=plan['record'] if plan['restore'] else {'format':1,'id':plan['id'],'state':'prepared',
                    'rows':[{'id':r['id'],'signature':r['signature'],'security':windows_security(self.paths[r['id']]).decode('utf-8') if os.name=='nt' else ''}
                            for r in plan['rows'] if r['id'] in plan['selected'] and not r['id'].startswith('system.')],
                    'system_record':plan['id'] if any(r.startswith('system.') for r in plan['selected']) else '',
                    'system_rows':[r for r in plan['rows'] if r['id'] in plan['selected'] and r['id'].startswith('system.')], 'at':time.time()}
                self._save(record,'restoring' if plan['restore'] else 'retiring_jobs')
                if plan['job_plan']:
                    result=self.components.apply(plan['job_plan']['plan_id'],True)
                    if result.get('state')!='completed':raise ValueError('旧任务停用未完成，程序保留，请先核对旧任务恢复入口')
                with self.transaction_lock():
                    self._quiet()
                    if any(r.get('present') is not False or r.get('registered') is not False for r in self._jobs()['rows']):
                        raise ValueError('旧后台任务仍存在或重新出现，未继续移动程序')
                    self._save(record,'restoring' if plan['restore'] else 'moving')
                    for row in record['rows']:
                        self._quiet()
                        if any(r.get('present') or r.get('registered') for r in self._jobs()['rows']):raise ValueError('旧任务重新出现，已停止移动')
                        path=self.paths[row['id']];backup=self._backup(path,record['id'],row['id'])
                        source,destination=(backup,path) if plan['restore'] else (path,backup)
                        current=signature(source);existing=signature(destination)
                        if plan['restore'] and current is None and existing==row['signature']:
                            if os.name=='nt' and row['security']:restore_windows_security(destination,row['security'])
                            continue
                        if current!=row['signature'] or existing is not None:raise ValueError('原文件或存档已改变，未覆盖；请手动核对两个副本')
                        if not plan['restore']:
                            _safe_chain(backup.parent)
                            if not backup.parent.exists():backup.parent.mkdir(mode=0o700)
                            restrict_private_directory(backup.parent)
                        rename_exclusive(source,destination)
                        if plan['restore'] and os.name=='nt' and row['security']:restore_windows_security(destination,row['security'])
                        if signature(source) is not None or signature(destination)!=row['signature']:raise ValueError('移动后摘要未通过，保留现场')
                    if record['system_record']:
                        selected=[r.removeprefix('system.') for r in plan['selected'] if r.startswith('system.')]
                        payload={'format':1,'actor':plan['jobs']['actor'],'id':record['system_record'],'roles':selected,
                                 'expected_record':plan['system_record'].get('id',''),
                                 'before':[{**r,'id':r['id'].removeprefix('system.')} for r in plan['rows'] if r['id'].startswith('system.')]}
                        # A crash before the root transaction began needs no
                        # root restore if every approved source still matches.
                        root_not_started=(plan['restore'] and plan['system_record'].get('id')!=record['system_record'])
                        if root_not_started:
                            live={r['id']:r for r in self.system_files.snapshot()}
                            if any(any(live.get(r['id'],{}).get(k)!=r.get(k) for k in ('present','sha256','mode','group')) for r in record['system_rows']):
                                raise ValueError('系统原文件发生变化且没有对应事务，请管理员核对，未覆盖')
                        else:self.system_files.execute('restore' if plan['restore'] else 'retire',payload)
                        after=self.system_files.status()
                        if not root_not_started and (after.get('id')!=record['system_record'] or after.get('state')!=('restored' if plan['restore'] else 'committed')):raise ValueError('系统程序清理尚未完整读回，保留恢复记录')
                    # Independent final readback covers the whole selection,
                    # including files moved before a slow system authorization.
                    for row in record['rows']:
                        path=self.paths[row['id']];backup=self._backup(path,record['id'],row['id'])
                        actual,archived=signature(path),signature(backup)
                        if (plan['restore'] and (actual!=row['signature'] or archived is not None)
                                or not plan['restore'] and (actual is not None or archived!=row['signature'])):
                            raise ValueError('最终程序读回发生变化，已保留存档，请重新核对')
                    live={r['id']:r for r in self.system_files.snapshot()}
                    for row in record['system_rows']:
                        now=live.get(row['id'],{})
                        if (plan['restore'] and any(now.get(k)!=row.get(k) for k in ('present','sha256','mode','group'))
                                or not plan['restore'] and now.get('present') is not False):
                            raise ValueError('最终系统文件读回未通过，请管理员核对原文件和存档')
                    if any(r.get('present') or r.get('registered') for r in self._jobs()['rows']):raise ValueError('旧任务在最终读回时重新出现，请先处理冲突')
                self._save(record,'restored' if plan['restore'] else 'committed');self.plans.clear()
                self.status()
                return {'state':'restored' if plan['restore'] else 'completed','needs_retest':True,
                        'reason':'旧程序已恢复，后台任务保持停用；需要时另行预览恢复原任务。' if plan['restore'] else '所选旧程序路径已移除，存档及账号资料保留；请根据复检结果审核 EnvScope 守护。'}
        except (OSError,ValueError,AccountError,subprocess.TimeoutExpired) as error:
            if record:
                try:
                    with self.locker._lock():
                        current=self._record()
                        if current and current['id']==record['id'] and current['state'] in PENDING:
                            self._save(current,'partial')
                except (OSError,ValueError,AccountError):pass
            return {'state':'partial' if record else 'guided','needs_retest':bool(record),'reason':str(error)[:280]}
