"""Read-only proxy discovery and reviewed current-user application lifecycle.

No program found on PATH is executed. Callers select a discovered application,
pin its bytes, disclose exit/launch effects, and explicitly opt into force stop.
"""
import ctypes
import hashlib
import math
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import time

from .accounts import _safe_chain


SPECS=(
    ('clash-verge','Clash Verge',('Clash Verge','clash-verge','Clash Verge Rev'),'clash-verge.exe'),
    ('flclash','FlClash',('FlClash',),'FlClash.exe'),
    ('shadowrocket','Shadowrocket',('Shadowrocket',),'Shadowrocket.exe'),
    ('clashx','ClashX',('ClashX','ClashX Pro'),'ClashX.exe'),
    ('surge','Surge',('Surge',),'Surge.exe'),
    ('wireguard','WireGuard',('WireGuard',),'wireguard.exe'),
    ('other','Mihomo Party',('Mihomo Party',),'Mihomo Party.exe'),
    ('other','Clash Nyanpasu',('Clash Nyanpasu',),'Clash Nyanpasu.exe'),
)
WINDOWS_MODES={'clash-verge','flclash','wireguard','other'}


def file_hash(path):
    path=Path(path);_safe_chain(path)
    if not path.is_file() or not 0<path.stat().st_size<=500*1024**2:
        raise ValueError('代理客户端文件缺失或超出核对范围')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024**2),b''):digest.update(chunk)
    return digest.hexdigest()


def path_key(path):return os.path.normcase(os.path.realpath(path))


def registry_candidates():
    """Only recognized uninstall names and paths; never run uninstall commands."""
    import winreg
    labels={label:(mode,label,exe) for mode,label,_,exe in SPECS if mode in WINDOWS_MODES}
    labels['Clash Verge Rev']=labels['Clash Verge']
    result=[]
    for hive in (winreg.HKEY_CURRENT_USER,winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY,winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive,r'Software\Microsoft\Windows\CurrentVersion\Uninstall',0,winreg.KEY_READ|view) as root:
                    for index in range(min(winreg.QueryInfoKey(root)[0],4096)):
                        try:
                            with winreg.OpenKey(root,winreg.EnumKey(root,index)) as key:
                                label=winreg.QueryValueEx(key,'DisplayName')[0]
                                if label not in labels:continue
                                mode,label,exe=labels[label]
                                try:location=winreg.QueryValueEx(key,'InstallLocation')[0]
                                except OSError:location=None
                                if isinstance(location,str) and location:
                                    result.append((mode,label,Path(os.path.expandvars(location))/exe,None))
                                try:icon=winreg.QueryValueEx(key,'DisplayIcon')[0]
                                except OSError:icon=None
                                if isinstance(icon,str):
                                    match=re.fullmatch(r'\s*"([^"]+\.exe)"(?:,\s*-?\d+)?\s*|\s*([^"\r\n]+\.exe)(?:,\s*-?\d+)?\s*',icon,re.I)
                                    if match:
                                        candidate=Path(os.path.expandvars(match[1] or match[2]))
                                        if candidate.name.casefold()==exe.casefold():result.append((mode,label,candidate,None))
                        except (OSError,ValueError,TypeError):continue
            except OSError:continue
    return result


def discover_apps(home=None,system=None,environ=None,registry=None,*,mac_roots=None):
    home=Path(home or Path.home()).resolve();system=system or platform.system()
    env=os.environ if environ is None else environ;candidates=[]
    if system=='Windows':
        roots=[Path(env.get('LOCALAPPDATA') or home/'AppData/Local')/'Programs',
               Path(env.get('ProgramFiles') or 'C:/Program Files')]
        for mode,label,folders,exe in SPECS:
            if mode in WINDOWS_MODES:
                candidates.extend((mode,label,root/folder/exe,None) for root in roots for folder in folders)
        if registry is not None or platform.system()=='Windows':
            candidates.extend((registry or registry_candidates)())
    elif system=='Darwin':
        for mode,label,folders,exe in SPECS:
            if mode == 'wireguard': continue  # The macOS app uses a different VPN API.
            for root in (mac_roots if mac_roots is not None else (Path('/Applications'),home/'Applications')):
                for folder in folders:
                    app=root/(folder+'.app');info=app/'Contents/Info.plist'
                    try:
                        _safe_chain(info)
                        if not info.is_file() or info.stat().st_size>1024**2:continue
                        value=plistlib.loads(info.read_bytes())
                        if not isinstance(value,dict):continue
                        binary=value.get('CFBundleExecutable')
                        if not isinstance(binary,str) or not binary or binary in ('.','..') or any(c in '/\\' or ord(c)<32 for c in binary):continue
                        candidates.append((mode,label,app/'Contents/MacOS'/binary,str(app)))
                    except (OSError,ValueError,TypeError,RuntimeError):continue
    result={}
    for mode,label,path,bundle in candidates:
        try:
            if system=='Windows' and str(path).startswith(('\\\\','//')):continue
            if not path.is_absolute():continue
            _safe_chain(path)
            if not path.is_file():continue
            path=path.resolve(strict=True);_safe_chain(path)
            key=path_key(path)
            result[key]={'id':hashlib.sha256(key.encode()).hexdigest()[:20],'mode':mode,'label':label,
                         'path':str(path),'bundle':bundle}
        except (OSError,ValueError,RuntimeError):continue
    return sorted(result.values(),key=lambda item:(item['label'],item['path']))


def quit_macos_pid(pid):
    """AppKit terminate requests normal app exit for this PID, without names."""
    ctypes.CDLL('/System/Library/Frameworks/AppKit.framework/AppKit')
    objc=ctypes.CDLL('/usr/lib/libobjc.A.dylib')
    objc.objc_getClass.argtypes=[ctypes.c_char_p];objc.objc_getClass.restype=ctypes.c_void_p
    objc.sel_registerName.argtypes=[ctypes.c_char_p];objc.sel_registerName.restype=ctypes.c_void_p
    objc.class_getClassMethod.argtypes=[ctypes.c_void_p,ctypes.c_void_p];objc.class_getClassMethod.restype=ctypes.c_void_p
    address=ctypes.cast(objc.objc_msgSend,ctypes.c_void_p).value
    send=ctypes.CFUNCTYPE(ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p)(address)
    send_pid=ctypes.CFUNCTYPE(ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int)(address)
    send_bool=ctypes.CFUNCTYPE(ctypes.c_bool,ctypes.c_void_p,ctypes.c_void_p)(address)
    selector=objc.sel_registerName
    running_class=objc.objc_getClass(b'NSRunningApplication')
    running_selector=selector(b'runningApplicationWithProcessIdentifier:')
    if not running_class or not objc.class_getClassMethod(running_class,running_selector):
        raise ValueError('系统应用退出接口不可用，请在客户端手动退出后重试')
    pool=send(send(objc.objc_getClass(b'NSAutoreleasePool'),selector(b'alloc')),selector(b'init'))
    try:
        app=send_pid(running_class,running_selector,pid)
        return bool(app and send_bool(app,selector(b'terminate')))
    finally:
        ctypes.CFUNCTYPE(None,ctypes.c_void_p,ctypes.c_void_p)(address)(pool,selector(b'drain'))


class AppLifecycle:
    def __init__(self,home=None,system=None,ps=None,runner=None,launcher=None,mac_quit=None,sleeper=None,clock=None):
        if ps is None:
            import psutil as ps
        self.ps=ps;self.home=Path(home or Path.home()).resolve();self.system=system or platform.system()
        self.runner=runner or subprocess.run;self.launcher=launcher or subprocess.Popen
        self.mac_quit=mac_quit or quit_macos_pid;self.sleep=sleeper or time.sleep;self.clock=clock or time.monotonic

    def snapshot(self,app):
        own=self.ps.Process().username();rows=[];unreadable=False
        if not isinstance(own,str) or not own:raise ValueError('当前用户身份无法读取')
        wanted=path_key(app['path']);name=Path(app['path']).name.casefold()
        for process in self.ps.process_iter(['pid','name','exe','create_time','username'],ad_value=None):
            item=process.info
            if str(item.get('name') or '').casefold()!=name:continue
            if item.get('username') not in (None,own):continue
            if (not item.get('username') or not item.get('exe') or type(item.get('pid')) is not int or item['pid']<=0
                    or type(item.get('create_time')) not in (float,int) or not math.isfinite(item['create_time']) or item['create_time']<=0):
                unreadable=True;continue
            if path_key(item['exe'])==wanted:
                if item['pid']==os.getpid():
                    unreadable=True;continue
                rows.append({'pid':item['pid'],'created':item['create_time'],'exe':item['exe'],'owner':own})
        if len(rows)>32:raise ValueError('客户端进程数量异常，请先在客户端处理')
        return {'processes':rows,'unreadable':unreadable}

    def _same(self,identity,app):
        try:
            process=self.ps.Process(identity['pid'])
            same=(process.create_time()==identity['created'] and process.username()==identity['owner']
                  and process.username()==self.ps.Process().username() and path_key(process.exe())==path_key(app['path']))
            return process if same else None
        except (self.ps.Error,OSError,ValueError):return None

    def _request_exit(self,identity,app):
        if not self._same(identity,app):return
        if self.system=='Darwin':self.mac_quit(identity['pid']);return
        if self.system!='Windows':raise ValueError('当前系统没有正常退出适配器')
        from .system_network_windows import powershell,quote
        # No application name is used. Recheck the selected PID's birth, owner
        # and full executable path in the process issuing the window request.
        source=("$ErrorActionPreference='Stop';$env:PSModulePath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/Modules';"
                "$p=Get-Process -Id "+str(identity['pid'])+" -ErrorAction SilentlyContinue;if(-not $p){exit 0};"
                "$born=($p.StartTime.ToUniversalTime()-[DateTime]::SpecifyKind([DateTime]'1970-01-01','Utc')).TotalSeconds;"
                "if([Math]::Abs($born-"+format(identity['created'],'.6f')+") -gt 0.01 -or $p.Path -ine "+quote(app['path'])+"){exit 2};"
                "$c=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.Id);$o=Invoke-CimMethod -InputObject $c -MethodName GetOwner;"
                "if(($o.Domain+'\\'+$o.User) -ine "+quote(identity['owner'])+"){exit 2};"
                "if(-not $p.HasExited -and $p.MainWindowHandle -ne 0){[void]$p.CloseMainWindow()}")
        result=self.runner([powershell(),'-NoProfile','-NonInteractive','-Command',source],capture_output=True,timeout=12,
                           creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode:raise ValueError('客户端进程身份已变化，未提交退出请求')

    def stop(self,app,allow_force=False):
        if type(allow_force) is not bool:raise ValueError('强制退出需要明确的布尔选项')
        if file_hash(app['path'])!=app['sha256']:raise ValueError('代理客户端文件已更新，请重新审核')
        before=self.snapshot(app)
        if before['unreadable']:raise ValueError('客户端进程所属用户或路径无法读取，未停止进程')
        for identity in before['processes']:self._request_exit(identity,app)
        deadline=self.clock()+8
        while self.clock()<deadline:
            current=self.snapshot(app)
            if current['unreadable']:raise ValueError('退出期间进程归属无法确认')
            if not current['processes']:return {'stopped':True,'forced':False}
            # A replacement instance is not one of the approved identities.
            if any(row not in before['processes'] for row in current['processes']):
                raise ValueError('退出期间出现新的客户端实例，未继续停止')
            self.sleep(.25)
        if not allow_force:return {'stopped':False,'forced':False}
        for identity in before['processes']:
            process=self._same(identity,app)
            if process:
                try:process.terminate()
                except self.ps.NoSuchProcess:pass
        self.sleep(2)
        for identity in before['processes']:
            process=self._same(identity,app)
            if process:
                try:process.kill()
                except self.ps.NoSuchProcess:pass
        deadline=self.clock()+3
        while self.clock()<deadline:
            current=self.snapshot(app)
            if current['unreadable']:raise ValueError('强制退出后进程归属无法确认')
            if not current['processes']:return {'stopped':True,'forced':True}
            self.sleep(.25)
        return {'stopped':False,'forced':True}

    def start(self,app):
        if file_hash(app['path'])!=app['sha256']:raise ValueError('代理客户端文件已更新，未运行新的文件')
        current=self.snapshot(app)
        if current['unreadable']:raise ValueError('客户端进程归属无法读取')
        if current['processes']:return {'requested':False,'already_running':True}
        if self.system=='Darwin':
            bundle=Path(app.get('bundle') or '')
            if bundle/'Contents/MacOS'/Path(app['path']).name!=Path(app['path']):raise ValueError('客户端应用路径不符')
            result=self.runner(['/usr/bin/open','-g',str(bundle)],capture_output=True,timeout=12)
            if result.returncode:raise ValueError('客户端启动请求未完成')
        elif self.system=='Windows':
            self.launcher([app['path']],cwd=str(Path(app['path']).parent),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)|getattr(subprocess,'DETACHED_PROCESS',0))
        else:raise ValueError('当前系统没有客户端启动适配器')
        return {'requested':True,'already_running':False}
