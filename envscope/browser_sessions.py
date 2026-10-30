"""Private, restartable temporary browser cleanup; never touch daily profiles.

Only opaque session names under an explicit browser-sessions root are accepted.
The independent worker never launches or stops a browser and never probes the
network. Unknown processes or malformed records retain their data.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from itertools import islice

import psutil

from .accounts import AccountError, _safe_chain
from .event_log import append_event
from .snapshot_archive import restrict_private_directory

TOKEN = re.compile(r'[0-9a-f]{32}\Z')
MARKER = 'session.private.json'
MAX_SESSIONS = 256
FIELDS = {'format','token','created','cleanup_authorized','pid','birth','owner_pid','owner_birth','phase'}
NOTES = {'created':'已创建受保护的临时会话。','launched':'已记录启动进程身份。',
         'process_running':'启动进程仍在运行，资料保留。','process_unknown':'无法确认启动进程已退出，资料保留。',
         'profile_in_use_or_unknown':'仍有进程使用资料，或相关进程无法读取，暂不清理。',
         'record_unverified':'目录归属或会话记录异常，未自动清理；请手动核实。',
         'cleanup_failed':'清理未完成，恢复记录保留；退出临时浏览器后可重试。',
         'cleanup_started':'已确认本轮清理范围，开始移除临时资料。','removed':'临时资料已移除。',
         'started':'独立清理进程已启动。','stopped':'独立清理进程已结束。'}


def process_birth(pid):
    if type(pid) is not int or pid <= 0:
        return None
    try:
        return psutil.Process(pid).create_time()
    except (psutil.Error, OSError):
        return None


def process_alive(pid, birth):
    if type(pid) is not int or pid <= 0:
        return None
    try:
        process = psutil.Process(pid)
        if birth is None:
            return None
        if abs(process.create_time()-birth) > .01:
            return False  # A reused PID is not the original launcher.
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except (psutil.Error, OSError):
        return None


def profile_running(profile, system, created=None):
    if system not in ('Windows','Darwin'):
        return None
    names = {'chrome','chrome.exe','msedge','msedge.exe','brave','brave.exe','chromium','chromium.exe',
             'google chrome','microsoft edge','brave browser'}
    unknown = False
    needle = os.path.normcase(str(profile)).casefold()
    def older_unrelated(process):
        # The random profile token did not exist before creation. An older
        # process with an unreadable command cannot have received that new
        # --user-data-dir argument. Use a full second of timestamp tolerance.
        if created is None or not _number(created) or created > time.time()+1:
            return False
        try:
            return process.create_time() < created-1
        except (psutil.Error,OSError):
            return False
    try:
        for process in psutil.process_iter(['name']):
            try:
                name = process.info.get('name')
                if not name:
                    unknown = unknown or not older_unrelated(process)
                    continue
                if name.casefold() not in names:
                    continue
                args = process.cmdline()
                if not args:
                    unknown = unknown or not older_unrelated(process)
                elif any(needle in os.path.normcase(arg).casefold() for arg in args):
                    return True
            except psutil.NoSuchProcess:
                continue
            except (psutil.Error, OSError):
                unknown = unknown or not older_unrelated(process)
    except (psutil.Error, OSError):
        return None
    return None if unknown else False


def _number(value):
    return type(value) in (int,float) and math.isfinite(value) and value > 0


def _unique_object(pairs):
    value = {}
    for key,item in pairs:
        if key in value:
            raise AccountError('会话记录含重复字段，资料已保留。')
        value[key] = item
    return value


def _read_descriptor(path):
    if os.name != 'nt':
        return os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    # Metadata is replaced atomically by the independent worker. CRT opens do
    # not share deletion on Windows; use a read handle that permits replacement.
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    create=kernel.CreateFileW
    create.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    create.restype=wintypes.HANDLE
    close=kernel.CloseHandle;close.argtypes=[wintypes.HANDLE];close.restype=wintypes.BOOL
    handle=create(str(path),0x80000000,7,None,3,0x00200080,None)
    if handle==ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except BaseException:
        close(handle)
        raise


def _read_once(path):
    _safe_chain(path)
    before = path.lstat()
    # A concurrent rename can unlink the inode after lstat selected it. The
    # descriptor below is authoritative; zero links is safe for this read-only
    # metadata snapshot, whereas multiple links remain forbidden.
    if not stat.S_ISREG(before.st_mode) or before.st_nlink > 1 or before.st_size > 8192:
        raise AccountError('临时会话记录不是独立普通文件，资料已保留。')
    fd = _read_descriptor(path)
    with os.fdopen(fd,'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink > 1 or info.st_size > 8192
                or getattr(info,'st_file_attributes',0) & 0x400
                or os.name != 'nt' and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
            raise AccountError('临时会话记录的归属、权限或类型异常，资料已保留。')
        data = stream.read(8193)
        if len(data) > 8192:
            raise AccountError('临时会话记录过大，资料已保留。')
    return json.loads(data.decode('utf-8'),object_pairs_hook=_unique_object)


def _read(path):
    for attempt in range(3):
        try:
            return _read_once(path)
        except PermissionError:
            if attempt==2:
                raise
            time.sleep(.01)


def _write(path, value):
    _safe_chain(path)
    temporary = path.with_name(path.name+'.'+os.urandom(8).hex()+'.part')
    try:
        fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0), 0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(json.dumps(value,separators=(',',':')).encode('utf-8'))
            stream.flush();os.fsync(stream.fileno())
        if path.exists():
            _read(path)  # Never replace a link, shared file or unowned record.
        for attempt in range(8):
            try:
                os.replace(temporary,path)
                break
            except PermissionError:
                # Windows metadata queries and antivirus can briefly keep a
                # non-delete-sharing handle. Never rewrite the destination in
                # place, or hide a persistent denial.
                if os.name != 'nt' or attempt == 7:
                    raise
                time.sleep(.01*(attempt+1))
    finally:
        if temporary.exists():
            temporary.unlink()


class SessionStore:
    def __init__(self, root, system=None, *, running=None, alive=None, clock=time.time, pause=time.sleep):
        self.root = Path(root).absolute()
        if self.root.name != 'browser-sessions' or self.root.parent.name != '.envscope':
            raise AccountError('临时资料根目录不符合固定范围。')
        self.system = system or platform.system()
        self.running = running
        self.alive = alive or process_alive
        self.clock, self.pause = clock, pause
        self.last_events = {}

    def observed_running(self, profile, created):
        return self.running(profile) if self.running else profile_running(profile,self.system,created)

    def worker_status(self):
        path = self.root.parent/'browser-cleanup-worker.private.json'
        try:
            if not os.path.lexists(path):
                return {'state':'not_running'}
            value = _read(path)
            if (not isinstance(value,dict) or set(value)!={'format','pid','birth','at','state'}
                    or type(value['format']) is not int or value['format']!=1
                    or type(value['pid']) is not int or not _number(value['birth']) or not _number(value['at'])
                    or value['state'] not in ('running','stopped')):
                raise ValueError('invalid worker identity')
            if value['state']=='stopped':
                return {'state':'not_running'}
            alive = self.alive(value['pid'],value['birth'])
            if alive is not True:
                return {'state':'not_running' if alive is False else 'unverified'}
            args = psutil.Process(value['pid']).cmdline()
            index = args.index('--root')
            if (not ('--browser-cleanup-worker' in args or 'envscope.browser_sessions' in args)
                    or Path(args[index+1]).absolute()!=self.root):
                raise ValueError('worker command mismatch')
            if not 0 <= self.clock()-value['at'] <= 90:
                return {'state':'stale'}
            return {'state':'running','pid':value['pid'],'birth':value['birth']}
        except (OSError,ValueError,AccountError,psutil.Error,IndexError,UnicodeError,RecursionError):
            return {'state':'unverified'}

    def heartbeat(self, state):
        _write(self.root.parent/'browser-cleanup-worker.private.json',
               {'format':1,'pid':os.getpid(),'birth':process_birth(os.getpid()),'at':self.clock(),'state':state})

    @contextmanager
    def lock(self, worker=False):
        _safe_chain(self.root)
        self.root.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path = self.root.parent/('.browser-cleanup-worker.lock' if worker else '.browser-sessions.lock')
        _safe_chain(path)
        fd = os.open(path,os.O_RDWR|os.O_CREAT|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'r+b') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AccountError('临时会话锁类型异常。')
            if not info.st_size:
                stream.write(b'0');stream.flush()
            stream.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:
                raise AccountError('临时浏览器清理正在执行，请稍后重试。') from None
            try:
                yield
            finally:
                stream.seek(0)
                if os.name == 'nt':
                    msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
                else:
                    fcntl.flock(stream.fileno(),fcntl.LOCK_UN)

    def _event(self, token, state):
        if self.last_events.get(token) == state:
            return
        append_event(self.root.parent/'browser-cleanup-events',
                     {'at':datetime.now(timezone.utc).isoformat(),'session':token,'state':state,'note':NOTES[state]})
        self.last_events[token] = state

    def _directory(self, path):
        _safe_chain(path)
        info = path.stat()
        if (not stat.S_ISDIR(info.st_mode) or os.name != 'nt' and info.st_uid != os.getuid()
                or path.parent != self.root or path.resolve().parent != self.root.resolve()):
            raise AccountError('临时资料目录的范围或归属异常，资料已保留。')

    def entries(self):
        with os.scandir(self.root) as entries:
            for item in islice(entries,MAX_SESSIONS+1):
                yield Path(item.path)

    def read(self, token):
        if not isinstance(token,str) or not TOKEN.fullmatch(token):
            raise AccountError('临时会话代号无效。')
        directory = self.root/token
        self._directory(directory)
        value = _read(directory/MARKER)
        if (not isinstance(value,dict) or set(value) != FIELDS or type(value.get('format')) is not int
                or value['format'] != 1 or value['token'] != token or value['cleanup_authorized'] is not True
                or not _number(value['created']) or value['created']>self.clock()+60 or value['phase'] not in ('starting','ready','cleaning')
                or any(v is not None and (type(v) is not int or not 0 < v < 2**32) for v in (value['pid'],value['owner_pid']))
                or any(v is not None and not _number(v) for v in (value['birth'],value['owner_birth']))):
            raise AccountError('临时会话记录无效或未授权清理，资料已保留。')
        return value

    def inspect(self):
        result = {'sessions':0,'legacy':0,'unverified':0,'pending':0,'overflow':False}
        _safe_chain(self.root)
        if not self.root.exists():
            return result
        with os.scandir(self.root) as entries:
            for index,entry in enumerate(entries):
                if index >= MAX_SESSIONS:
                    result['overflow'] = True
                    break
                path = Path(entry.path)
                try:
                    self._directory(path)
                    if not TOKEN.fullmatch(path.name):
                        raise AccountError('unrecognized directory')
                    if not os.path.lexists(path/MARKER):
                        result['legacy'] += 1
                        continue
                    value = self.read(path.name)
                    result['sessions'] += 1
                    result['pending'] += value['phase']=='cleaning'
                except (OSError,ValueError,AccountError,UnicodeError,RecursionError):
                    result['unverified'] += 1
        return result

    def create(self, token):
        if not isinstance(token,str) or not TOKEN.fullmatch(token):
            raise AccountError('临时会话代号无效。')
        with self.lock():
            self.root.mkdir(mode=0o700,exist_ok=True)
            with os.scandir(self.root) as entries:
                if sum(1 for _ in islice(entries,MAX_SESSIONS)) >= MAX_SESSIONS:
                    raise AccountError('临时资料过多，请先清理已关闭的会话。')
            directory = self.root/token
            directory.mkdir(mode=0o700)
            restrict_private_directory(directory)
            value = {'format':1,'token':token,'created':self.clock(),'cleanup_authorized':True,
                     'pid':None,'birth':None,'owner_pid':os.getpid(),'owner_birth':process_birth(os.getpid()),'phase':'starting'}
            _write(directory/MARKER,value)
            profile = directory/'profile';profile.mkdir(mode=0o700)
            self._event(token,'created')
        return profile

    def launched(self, token, process):
        with self.lock():
            value = self.read(token)
            pid = getattr(process,'pid',None)
            value.update(pid=pid if type(pid) is int else None,birth=process_birth(pid),phase='ready')
            _write(self.root/token/MARKER,value)
            self._event(token,'launched')

    def abandon(self, token):
        """A failed launch can remove only this creator's still-empty profile."""
        with self.lock():
            value = self.read(token)
            profile = self.root/token/'profile'
            if (value['phase'] != 'starting' or value['owner_pid'] != os.getpid()
                    or profile.exists() and any(profile.iterdir())):
                return False
            self._remove(token)
            return True

    def _remove(self, token, legacy=False):
        directory = self.root/token
        self._directory(directory)
        if legacy:
            profile = directory
        else:
            value = self.read(token)
            with os.scandir(directory) as entries:
                if set(p.name for p in islice(entries,3)) - {MARKER,'profile'}:
                    raise AccountError('会话目录含额外文件，资料已保留。')
            value['phase']='cleaning';_write(directory/MARKER,value)
            profile = directory/'profile'
        self._event(token,'cleanup_started')
        _safe_chain(profile)
        if profile.exists():
            if self.root.resolve() not in profile.resolve().parents:
                raise AccountError('临时资料路径发生变化。')
            shutil.rmtree(profile)
        if not legacy:
            marker = directory/MARKER
            try:
                marker.unlink()
                directory.rmdir()
            except OSError:
                if directory.exists() and not os.path.lexists(marker):
                    self._directory(directory)
                    _write(marker,value)
                raise
        self._event(token,'removed')

    def cleanup(self, token=None, *, allow_legacy=False, local=None):
        if token is not None and (not isinstance(token,str) or not TOKEN.fullmatch(token)):
            raise AccountError('临时会话代号无效。')
        local = local or {}
        result = {'state':'completed','removed':0,'retained':0,'unverified':0,'legacy':0,'overflow':False}
        if not self.root.exists():
            return result
        with self.lock():
            for index,directory in enumerate(self.entries()):
                if index >= MAX_SESSIONS:
                    result['overflow']=True;break
                key = directory.name
                if token and key != token:
                    continue
                removing = False
                try:
                    self._directory(directory)
                    if not TOKEN.fullmatch(key):
                        raise AccountError('unrecognized directory')
                    legacy = not os.path.lexists(directory/MARKER)
                    if legacy and not allow_legacy:
                        result['legacy'] += 1;continue
                    value = None if legacy else self.read(key)
                    profile = directory if legacy else directory/'profile'
                    info = directory.stat()
                    created = value['created'] if value else getattr(info,'st_birthtime',None)
                    if key in local:
                        live = local[key]
                    elif legacy:
                        live = False
                    elif value['phase']=='starting' or value['phase']=='cleaning' and value['pid'] is None:
                        live = self.alive(value['owner_pid'],value['owner_birth'])
                        # A crash before recording the child PID remains a
                        # recoverable unknown, never an inferred closed session.
                        if live is False:
                            live = False if value['phase']=='cleaning' or allow_legacy and self.clock()-value['created'] >= 30 else None
                    else:
                        live = self.alive(value['pid'],value['birth'])
                    if live is not False:
                        result['retained'] += 1;self._event(key,'process_running' if live is True else 'process_unknown');continue
                    if self.observed_running(profile,created) is not False:
                        result['retained'] += 1;self._event(key,'profile_in_use_or_unknown');continue
                    self.pause(.15)
                    if self.observed_running(profile,created) is not False:
                        result['retained'] += 1;self._event(key,'profile_in_use_or_unknown');continue
                    removing = True
                    self._remove(key,legacy)
                    result['removed'] += 1
                except (OSError,ValueError,AccountError,UnicodeError,RecursionError):
                    result['unverified'] += 1
                    try:
                        self._event(key if TOKEN.fullmatch(key) else 'unknown','cleanup_failed' if removing else 'record_unverified')
                    except (OSError,ValueError,AccountError):
                        pass  # No deletion is hidden by a fabricated log success.
            if result['unverified'] or result['overflow']:
                result['state']='partial'
        return result


def start_worker(root, poll_interval=15):
    if type(poll_interval) not in (int,float) or not math.isfinite(poll_interval) or not 1 <= poll_interval <= 60:
        raise ValueError('cleanup interval outside range')
    args = ([sys.executable,'--browser-cleanup-worker'] if getattr(sys,'frozen',False)
            else [sys.executable,'-m','envscope.browser_sessions']) + ['--root',str(root),'--poll-interval',str(poll_interval)]
    options = dict(stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
    if os.name == 'nt':
        options['creationflags'] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options['start_new_session'] = True
    return subprocess.Popen(args,**options)


def validate_fixture_root(root):
    """Test entry cannot reach user profiles, apps or an arbitrary output root."""
    root = Path(root).absolute()
    _safe_chain(root)
    if (not root.is_dir() or root.resolve().parent != Path(tempfile.gettempdir()).resolve()
            or not root.name.startswith('envscope-browser-acceptance-')):
        raise AccountError('浏览器验收仅接受调用方创建的专用临时目录。')
    return root


def fixture_parent(root):
    """Owned sleeping process stands in for a browser; parent exits first."""
    root = validate_fixture_root(root)
    if platform.system() not in ('Windows','Darwin'):
        raise AccountError('Native browser cleanup acceptance targets Windows and macOS.')
    if (root/'fixture-result.private.json').exists():
        raise AccountError('验收结果已经存在，未覆盖。')
    store = SessionStore(root/'.envscope/browser-sessions')
    token = 'b'*32
    profile = store.create(token)
    (profile/'Cookies').write_bytes(b'OWNED_BROWSER_SESSION_FIXTURE_ONLY')
    command = ([str(Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'),
                '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 15']
               if platform.system()=='Windows' else ['/bin/sleep','15'])
    sleeper = subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    store.launched(token,sleeper)
    worker = start_worker(store.root,poll_interval=1)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline and store.worker_status().get('state')!='running':
        time.sleep(.05)
    if store.worker_status().get('state')!='running':
        raise AccountError('隔离验收清理进程没有在期限内读回。')
    _write(root/'fixture-result.private.json',{'format':1,'token':token,'parent_pid':os.getpid(),
           'parent_birth':process_birth(os.getpid()),
           'sleeper_pid':sleeper.pid,'sleeper_birth':process_birth(sleeper.pid),
           'worker_pid':worker.pid,'worker_birth':process_birth(worker.pid)})
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='EnvScope 临时浏览器清理进程')
    parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--poll-interval',type=float,default=15)
    args = parser.parse_args(argv)
    if not math.isfinite(args.poll_interval) or not 1 <= args.poll_interval <= 60:
        parser.error('poll interval must be between 1 and 60 seconds')
    if not args.root.exists():
        return 0
    if platform.system() not in ('Windows','Darwin'):
        return 2
    store = SessionStore(args.root)
    try:
        with store.lock(worker=True):
            store._event('worker','started')
            while True:
                store.heartbeat('running')
                result = store.cleanup()
                status = store.inspect()
                if not status['sessions']:
                    break
                time.sleep(args.poll_interval)
            store._event('worker','stopped')
            store.heartbeat('stopped')
        return 0 if not (result['unverified'] or result['legacy'] or result['overflow']) else 2
    except (AccountError,OSError,ValueError):
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
