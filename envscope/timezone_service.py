"""Explicit installation of a narrowly scoped, root-owned macOS timezone job.

The administrator prompt receives a fixed script. A native worker is copied into
a root-only stage and checked against the reviewed SHA-256 before execution.
No Python runtime, user configuration, user log path, or vendor script runs as root.
"""
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
import time
import zipfile

from . import __release__
from .accounts import _safe_chain
from .region_profiles import profile
from .region_setup import current_region
from .remedies import SolutionPlans
from .target_environment import fingerprint
from .timezone_heartbeat import heartbeat_current


@dataclass(frozen=True)
class Layout:
    root: PurePosixPath = PurePosixPath('/Library/PrivilegedHelperTools/io.qudadd.envscope.timezone')
    daemon: PurePosixPath = PurePosixPath('/Library/LaunchDaemons/io.qudadd.envscope.timezone.plist')
    label: str = 'io.qudadd.envscope.timezone'


FILES = ('worker', 'baseline.plist', 'state.plist', 'status.plist')
ZONE = re.compile(r'[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+){0,3}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _zone(value):
    if not isinstance(value,str) or not ZONE.fullmatch(value):
        raise ValueError('时区标识无法安全读取，请在系统设置核对后重新检测。')
    return value


def _encoded(value):
    return base64.b64encode(value).decode('ascii')


def daemon_bytes(layout):
    return plistlib.dumps({'Label':layout.label,'ProgramArguments':[str(layout.root/'worker'),'--once'],
                          'RunAtLoad':True,'StartInterval':60,'ThrottleInterval':30,'ExitTimeOut':25,
                          'ProcessType':'Background','LowPriorityIO':True,'Nice':10,
                          'EnvironmentVariables':{'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C'},
                          'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null'},sort_keys=True)


def bundle_worker(root=None,cache=None,*,component='timezone',system='Darwin'):
    if component not in ('timezone','network','components'):raise ValueError('不支持的系统辅助程序')
    name=component+'-helper';binary=name+('.exe' if system=='Windows' else '');label={'timezone':'时区','network':'网络','components':'组件迁移'}[component]
    root=Path(root) if root is not None else Path(__file__).resolve().parent/'native-runtime'
    try:
        metadata=root/(name+'.json')
        if metadata.stat().st_size>65536:raise ValueError('oversized helper metadata')
        manifest=json.loads(metadata.read_text(encoding='utf-8'))
        payload=root/(name+'.payload.zip')
        if payload.stat().st_size>2*1024**2:raise ValueError('oversized helper payload')
        with zipfile.ZipFile(payload) as archive:
            if archive.namelist()!=[binary] or not 0<archive.getinfo(binary).file_size<=2*1024**2:
                raise ValueError('invalid helper payload')
            data=archive.read(binary)
    except (OSError,ValueError,zipfile.BadZipFile,RuntimeError):
        raise ValueError('请使用完整 '+('Windows' if system=='Windows' else 'macOS')+' 独立桌面包，本入口需要随附的原生'+label+'辅助程序。') from None
    if (not isinstance(manifest,dict) or type(manifest.get('format')) is not int or manifest.get('format')!=1
            or manifest.get('fixture') is not False or manifest.get('release')!=__release__
            or not isinstance(manifest.get('sha256'),str) or not SHA.fullmatch(manifest['sha256'])
            or _hash(data)!=manifest['sha256']):
        raise ValueError('随附的时区辅助程序校验失败，请重新获取完整桌面包。')
    # A compressed data resource keeps PyInstaller from rewriting Mach-O bytes.
    # Materialize as the ordinary user, then root independently copies/hashes it.
    uid=os.getuid() if hasattr(os,'getuid') else None
    base=Path(cache) if cache is not None else Path(tempfile.gettempdir()).resolve()/('envscope-'+component+'-'+str(uid))
    _safe_chain(base)
    base.mkdir(mode=0o700,parents=True,exist_ok=True)
    for directory in (base,base/manifest['sha256']):
        _safe_chain(directory)
        directory.mkdir(mode=0o700,exist_ok=True)
        info=directory.stat()
        if not stat.S_ISDIR(info.st_mode) or uid is not None and (info.st_uid!=uid or info.st_mode&0o077):
            raise ValueError('时区辅助程序缓存权限冲突，未执行。')
    path=base/manifest['sha256']/binary;_safe_chain(path)
    valid=False
    if path.exists():
        info=path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or uid is not None and (info.st_uid!=uid or info.st_mode&0o022)):
            raise ValueError('时区辅助程序缓存类型或权限冲突，未执行。')
        valid=info.st_size==len(data) and _hash(path.read_bytes())==manifest['sha256']
    if not valid:
        temporary=path.with_name('.helper-'+secrets.token_hex(12))
        try:
            descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o500)
            with os.fdopen(descriptor,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.chmod(temporary,0o500)
            os.replace(temporary,path)
        finally:temporary.unlink(missing_ok=True)
    if _hash(path.read_bytes())!=manifest['sha256']:raise ValueError('时区辅助程序缓存读回不一致，未执行。')
    return {'path':str(path),'sha256':manifest['sha256'],'release':manifest['release']}


def _header(layout):
    if (not layout.root.is_absolute() or not layout.daemon.is_absolute()
            or not re.fullmatch(r'[A-Za-z0-9.-]{1,100}',layout.label)):
        raise ValueError('invalid timezone service layout')
    return '''set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
umask 077
[ "$(/usr/bin/id -u)" = 0 ] || exit 77
ROOT=@ROOT@
DAEMON=@DAEMON@
JOB=@JOB@
PENDING="$ROOT/pending"
safe() {
  [ ! -L "$1" ] && [ -e "$1" ] || return 1
  [ "$(/usr/bin/stat -f %u "$1")" = 0 ] || return 1
  m=$(/usr/bin/stat -f %Lp "$1")
  case "$m" in ''|*[!0-7]*) return 1;; esac
  [ $((0$m & 022)) -eq 0 ] || return 1
  if [ -f "$1" ]; then [ "$(/usr/bin/stat -f %l "$1")" = 1 ] || return 1; fi
}
digest() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
registered() { /bin/launchctl print "$JOB" >/dev/null 2>&1; }
stop_job() {
  if registered; then /bin/launchctl bootout "$JOB" || return 1; fi
  n=0
  while registered; do n=$((n+1)); [ "$n" -le 30 ] || return 1; /bin/sleep 1; done
}
log() {
  p="$ROOT/install-events.private.jsonl"
  if [ -e "$p" ] || [ -L "$p" ]; then safe "$p" || return 1; fi
  /usr/bin/printf '{"at_epoch":%s,"kind":"timezone_service","phase":"%s"}\\n' "$(/bin/date +%s)" "$1" >> "$p"
  /bin/chmod 644 "$p"
}
'''.replace('@ROOT@',shlex.quote(str(layout.root))).replace('@DAEMON@',shlex.quote(str(layout.daemon))).replace('@JOB@',shlex.quote('system/'+layout.label))


def _expected_script(snapshot):
    lines=[]
    for name in ('worker','baseline.plist','daemon'):
        path='$DAEMON' if name=='daemon' else '$ROOT/'+name
        expected=snapshot['hashes'].get(name)
        if expected is None:
            lines.append(f'[ ! -e "{path}" ] && [ ! -L "{path}" ] || exit 79')
        else:
            if not SHA.fullmatch(expected):raise ValueError('invalid service checksum')
            lines.extend([f'safe "{path}" || exit 79',f'[ "$(digest "{path}")" = {shlex.quote(expected)} ] || exit 79'])
    lines.append('registered || exit 79' if snapshot['registered'] else 'if registered; then exit 79; fi')
    # Even an install/remove cycle with the same timezone and no remaining files
    # is a later operation. Recheck its receipt after the authorization dialog.
    for name in ('transaction','outcome'):
        value=snapshot.get(name,{})
        if value:
            expected=_hash(plistlib.dumps(value,sort_keys=True))
            lines.append(f'safe "$ROOT/{name}.plist" && [ "$(digest "$ROOT/{name}.plist")" = {shlex.quote(expected)} ] || exit 79')
        else:lines.append(f'[ ! -e "$ROOT/{name}.plist" ] && [ ! -L "$ROOT/{name}.plist" ] || exit 79')
    return '\n'.join(lines)+'\n'


def _receipt(snapshot, action, target=None, original=None):
    receipt={'format':1,'phase':'pending','operation':action,'nonce':secrets.token_hex(12),
            'before':_zone(snapshot['observed']),'target':_zone(target or snapshot['observed']),
            'original':_zone(original or snapshot['observed']),'registered':snapshot['registered'],
            'hashes':{k:v for k,v in snapshot['hashes'].items() if v is not None},'release':__release__}
    if snapshot.get('baseline'):receipt['previous_target']=_zone(snapshot['baseline']['target'])
    return receipt


def _outcome_script(receipt, state):
    data=plistlib.dumps({'format':1,'nonce':receipt['nonce'],'state':state},sort_keys=True)
    return (f'/usr/bin/printf %s {shlex.quote(_encoded(data))} | /usr/bin/base64 -D > "$ROOT/outcome.plist.next"\n'
            '/bin/chmod 644 "$ROOT/outcome.plist.next"\n/bin/mv -f "$ROOT/outcome.plist.next" "$ROOT/outcome.plist"\n')


def _stable(snapshot):
    return {k:v for k,v in snapshot.items() if k!='status'}


def _signature(snapshot):
    return _hash(json.dumps(_stable(snapshot),sort_keys=True).encode())


def privileged_script(layout,script,worker):
    """Verify a root-owned stage, then serialize the authorized transaction."""
    if not isinstance(worker.get('sha256'),str) or not SHA.fullmatch(worker['sha256']):
        raise ValueError('invalid native helper checksum')
    stage='stage-'+secrets.token_hex(12)
    body=_header(layout)+'''
parent=$(/usr/bin/dirname "$ROOT")
if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
  safe "$(/usr/bin/dirname "$parent")" || exit 79
  /bin/mkdir "$parent"; /bin/chmod 755 "$parent"; /bin/chmod -N "$parent"
fi
safe "$parent" || exit 79
if [ ! -e "$ROOT" ] && [ ! -L "$ROOT" ]; then /bin/mkdir "$ROOT"; /bin/chmod 755 "$ROOT"; /bin/chmod -N "$ROOT"; fi
safe "$ROOT" || exit 79
'''
    body+=f'STAGE="$ROOT/{stage}"\n/bin/mkdir "$STAGE"\n/bin/chmod 700 "$STAGE"\n/bin/chmod -N "$STAGE"\n'
    body+='''trap '/bin/rm -f "$STAGE/lock-worker"; /bin/rmdir "$STAGE"' EXIT
trap 'exit 130' INT TERM HUP
'''
    body+=f'/bin/cp {shlex.quote(worker["path"])} "$STAGE/lock-worker"\n/bin/chmod 755 "$STAGE/lock-worker"\n'
    body+=f'safe "$STAGE/lock-worker" && [ "$(digest "$STAGE/lock-worker")" = {shlex.quote(worker["sha256"])} ] || exit 79\n'
    body+=f'/usr/bin/printf %s {shlex.quote(_encoded(script.encode()))} | /usr/bin/base64 -D | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C HOME=/var/root "$STAGE/lock-worker" --lifecycle\n'
    return body


def render_transaction(layout, snapshot, worker, action, target=None, owner_uid=None, restore=False):
    if action not in ('install','remove'):raise ValueError('invalid timezone operation')
    if type(restore) is not bool:raise ValueError('invalid restore option')
    before=_zone(snapshot['observed'])
    original=snapshot.get('baseline',{}).get('original',before)
    original=_zone(original)
    receipt=_receipt(snapshot,action,target,original)
    receipt['owner_uid']=owner_uid
    new_baseline={'format':1,'target':_zone(target or before),'original':original,
                  'owner_uid':owner_uid,'helper_sha256':worker['sha256'],'release':__release__,
                  'installed_at':datetime.now(timezone.utc).isoformat()}
    # The script contains data literals only; no caller-supplied command reaches it.
    header=_header(layout)+'''
parent=$(/usr/bin/dirname "$ROOT")
if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
  safe "$(/usr/bin/dirname "$parent")" || exit 79
  /bin/mkdir "$parent"; /bin/chmod 755 "$parent"; /bin/chmod -N "$parent"
fi
safe "$(/usr/bin/dirname "$ROOT")" && safe "$(/usr/bin/dirname "$DAEMON")" || exit 79
if [ ! -e "$ROOT" ] && [ ! -L "$ROOT" ]; then /bin/mkdir "$ROOT"; /bin/chmod 755 "$ROOT"; /bin/chmod -N "$ROOT"; fi
safe "$ROOT" || exit 79
[ ! -e "$PENDING" ] && [ ! -L "$PENDING" ] || exit 79
'''+_expected_script(snapshot)
    header+='''
/bin/mkdir "$PENDING"
/bin/chmod 700 "$PENDING"
/bin/chmod -N "$PENDING"
'''
    # Safe metadata is public; backups and interrupted state remain root-only.
    encoded=shlex.quote(_encoded(plistlib.dumps(receipt,sort_keys=True)))
    header+=f'/usr/bin/printf %s {encoded} | /usr/bin/base64 -D > "$PENDING/receipt.plist"\n'
    header+='''/bin/cp "$PENDING/receipt.plist" "$ROOT/transaction.plist.next"
/bin/chmod 644 "$ROOT/transaction.plist.next"
/bin/mv -f "$ROOT/transaction.plist.next" "$ROOT/transaction.plist"
for name in worker baseline.plist state.plist status.plist; do
  if [ -e "$ROOT/$name" ] || [ -L "$ROOT/$name" ]; then safe "$ROOT/$name" || exit 79; /bin/cp -p "$ROOT/$name" "$PENDING/$name.old"; fi
done
if [ -e "$DAEMON" ]; then /bin/cp -p "$DAEMON" "$PENDING/daemon.old"; fi
'''
    # Keep a verified root-owned executable for rollback even on first install.
    source=shlex.quote(worker['path']);expected=shlex.quote(worker['sha256'])
    header+=f'/bin/cp {source} "$PENDING/rollback-worker"\n/bin/chmod 755 "$PENDING/rollback-worker"\n'
    header+=f'[ "$(digest "$PENDING/rollback-worker")" = {expected} ] || exit 79\n'
    header+='''safe "$PENDING/rollback-worker" || exit 79
'''
    header+=f'"$PENDING/rollback-worker" --check-zone {shlex.quote(before)} || exit 79\n'
    rollback='''
rollback() {
  set +e
  ok=1
  stop_job || ok=0
  for name in worker baseline.plist state.plist status.plist; do
    /bin/rm -f "$ROOT/$name" || ok=0
    if [ -f "$PENDING/$name.old" ]; then safe "$PENDING/$name.old" && /bin/cp -p "$PENDING/$name.old" "$ROOT/$name" || ok=0; fi
  done
  /bin/rm -f "$DAEMON" || ok=0
  if [ -f "$PENDING/daemon.old" ]; then safe "$PENDING/daemon.old" && /bin/cp -p "$PENDING/daemon.old" "$DAEMON" || ok=0; fi
  if [ "$restore_clock" = 1 ]; then "$PENDING/rollback-worker" --restore-zone @BEFORE@ || ok=0; fi
  if @REGISTERED@; then /bin/launchctl bootstrap system "$DAEMON" || ok=0; fi
  if [ "$ok" = 1 ]; then
    @ROLLED_BACK@
    /bin/mv "$PENDING" "$ROOT/backup-@NONCE@"
    log rollback_complete
  else
    log rollback_needed
  fi
}
finished=0
restore_clock=0
trap 'code=$?; if [ "$finished" = 0 ]; then rollback; fi; exit "$code"' EXIT
trap 'exit 130' INT TERM HUP
log transaction_started
stop_job
'''.replace('@BEFORE@',shlex.quote(before)).replace('@REGISTERED@','true' if snapshot['registered'] else 'false').replace('@NONCE@',receipt['nonce']).replace('@ROLLED_BACK@',_outcome_script(receipt,'rolled_back'))
    body=header+rollback+f'"$PENDING/rollback-worker" --check-zone {shlex.quote(before)}\n'
    if action=='install':
        body+='''/bin/cp "$PENDING/rollback-worker" "$ROOT/worker.next"
/bin/chmod 755 "$ROOT/worker.next"
/bin/mv -f "$ROOT/worker.next" "$ROOT/worker"
'''
        for path,data in [('$ROOT/baseline.plist',plistlib.dumps(new_baseline,sort_keys=True)),('$DAEMON',daemon_bytes(layout))]:
            body+=f'/usr/bin/printf %s {shlex.quote(_encoded(data))} | /usr/bin/base64 -D > "{path}.next"\n/bin/chmod 644 "{path}.next"\n/bin/mv -f "{path}.next" "{path}"\n'
        body+='''/bin/rm -f "$ROOT/state.plist" "$ROOT/status.plist"
restore_clock=1
"$ROOT/worker" --initial-apply
state=$(/usr/libexec/PlistBuddy -c 'Print :state' "$ROOT/status.plist")
case "$state" in healthy|restored) ;; *) exit 74;; esac
/bin/launchctl bootstrap system "$DAEMON"
registered || exit 74
'''
    else:
        if restore:body+=f'restore_clock=1\n"$PENDING/rollback-worker" --restore-zone {shlex.quote(original)}\n'
        body+='''for name in worker baseline.plist state.plist status.plist; do /bin/rm -f "$ROOT/$name"; done
/bin/rm -f "$DAEMON"
if registered; then exit 74; fi
'''
    body+=_outcome_script(receipt,'committed')+'''/bin/mv "$PENDING" "$ROOT/backup-@NONCE@"
finished=1
trap - EXIT INT TERM HUP
log transaction_committed
'''.replace('@NONCE@',receipt['nonce'])
    if action=='install':body+='/bin/launchctl kickstart "$JOB" || exit 74\n'
    body+="/usr/bin/printf '%s\\n' completed\n"
    return body,receipt


def render_recovery(layout,snapshot,worker):
    receipt=snapshot['transaction']
    if (receipt.get('format')!=1 or receipt.get('phase')!='pending'
            or not re.fullmatch('[a-f0-9]{24}',str(receipt.get('nonce','')))
            or type(receipt.get('registered')) is not bool or not isinstance(receipt.get('hashes'),dict)):
        raise ValueError('恢复记录无法安全识别，请手动核对系统服务备份。')
    before=_zone(receipt.get('before'));body=_header(layout)
    body+='safe "$ROOT" && safe "$PENDING" && safe "$ROOT/transaction.plist" && safe "$PENDING/receipt.plist" || exit 79\n'
    expected=_hash(plistlib.dumps(receipt,sort_keys=True))
    body+=f'[ "$(digest "$ROOT/transaction.plist")" = {shlex.quote(expected)} ] || exit 79\n'
    body+=f'[ "$(digest "$PENDING/receipt.plist")" = {shlex.quote(expected)} ] || exit 79\n'
    for name in ('worker','baseline.plist','daemon'):
        old=receipt['hashes'].get(name)
        backup='$PENDING/'+name+'.old'
        if old is None:
            body+=f'[ ! -e "{backup}" ] && [ ! -L "{backup}" ] || exit 79\n'
        else:
            if not isinstance(old,str) or not SHA.fullmatch(old):raise ValueError('恢复校验值无效')
            body+=f'safe "{backup}" && [ "$(digest "{backup}")" = {shlex.quote(old)} ] || exit 79\n'
    body+=f'/bin/cp {shlex.quote(worker["path"])} "$PENDING/recovery-worker"\n/bin/chmod 755 "$PENDING/recovery-worker"\n'
    body+=f'safe "$PENDING/recovery-worker" && [ "$(digest "$PENDING/recovery-worker")" = {shlex.quote(worker["sha256"])} ] || exit 79\n'
    body+='''stop_job
for name in worker baseline.plist state.plist status.plist; do
  /bin/rm -f "$ROOT/$name"
  if [ -f "$PENDING/$name.old" ]; then safe "$PENDING/$name.old"; /bin/cp -p "$PENDING/$name.old" "$ROOT/$name"; fi
done
/bin/rm -f "$DAEMON"
if [ -f "$PENDING/daemon.old" ]; then /bin/cp -p "$PENDING/daemon.old" "$DAEMON"; fi
'''
    body+=f'"$PENDING/recovery-worker" --restore-zone {shlex.quote(before)}\n'
    if receipt['registered']:body+='/bin/launchctl bootstrap system "$DAEMON"\nregistered || exit 74\n'
    body+=_outcome_script(receipt,'restored')+f'/bin/mv "$PENDING" "$ROOT/backup-{receipt["nonce"]}"\n'
    body+='log recovery_complete\n'
    return body


def render_undo(layout,snapshot,worker):
    receipt=snapshot['transaction']
    recovery=render_recovery(layout,snapshot,worker)  # Validate before rendering any mutation.
    if snapshot.get('outcome')!={'format':1,'nonce':receipt['nonce'],'state':'committed'}:
        raise ValueError('上次操作没有可撤销的提交记录，请先刷新或恢复未完成操作。')
    body=_header(layout)+_expected_script(snapshot)
    body+='safe "$ROOT" && [ ! -e "$PENDING" ] && [ ! -L "$PENDING" ] || exit 79\n'
    for name,value in (('transaction',receipt),('outcome',snapshot['outcome'])):
        body+=f'safe "$ROOT/{name}.plist" && [ "$(digest "$ROOT/{name}.plist")" = {shlex.quote(_hash(plistlib.dumps(value,sort_keys=True)))} ] || exit 79\n'
    # The bundled executable is staged and verified again before the compare.
    body+=f'/bin/cp {shlex.quote(worker["path"])} "$ROOT/undo-worker.next"\n/bin/chmod 755 "$ROOT/undo-worker.next"\n'
    body+=f'safe "$ROOT/undo-worker.next" && [ "$(digest "$ROOT/undo-worker.next")" = {shlex.quote(worker["sha256"])} ] || exit 79\n'
    body+=f'"$ROOT/undo-worker.next" --check-zone {shlex.quote(_zone(snapshot["observed"]))}\n/bin/rm -f "$ROOT/undo-worker.next"\n'
    body+=f'BACKUP="$ROOT/backup-{receipt["nonce"]}"\nsafe "$BACKUP" && safe "$BACKUP/receipt.plist" || exit 79\n'
    body+=f'[ "$(digest "$BACKUP/receipt.plist")" = {shlex.quote(_hash(plistlib.dumps(receipt,sort_keys=True)))} ] || exit 79\n'
    body+='/bin/mv "$BACKUP" "$PENDING"\n'
    return body+recovery


class NativeTimezoneIO:
    def __init__(self, layout=None, runner=None, worker=None, clock=None, fixture=False):
        self.layout=layout or Layout();self.runner=runner or self._run;self.worker=worker or bundle_worker
        self.clock=clock or time.time;self.fixture=fixture

    @staticmethod
    def _run(command, **kwargs):
        return subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',**kwargs)

    def read(self,path,limit=65536):
        path=Path(path)
        _safe_chain(path)
        if not path.exists():return None
        info=path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or info.st_size>limit):
            raise ValueError('时区服务文件权限或类型不符合预期。')
        return path.read_bytes()

    def inspect(self):
        root=Path(self.layout.root)
        _safe_chain(root)
        if root.exists():
            info=root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                raise ValueError('时区服务目录权限冲突，请先手动核对。')
        hashes={}
        for name,path in [('worker',root/'worker'),('baseline.plist',root/'baseline.plist'),('daemon',self.layout.daemon)]:
            data=self.read(path,2*1024**2 if name=='worker' else 65536)
            hashes[name]=_hash(data) if data is not None else None
        values={}
        for name in ('baseline','status','transaction','outcome'):
            body=self.read(root/(name+'.plist'))
            value=plistlib.loads(body) if body is not None else {}
            if not isinstance(value,dict):raise ValueError('时区服务记录格式无效。')
            values[name]=value
        result=self.runner(['/bin/launchctl','print','system/'+self.layout.label],timeout=5,
                           env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C'})
        if result.returncode==0:registered=True
        elif 'could not find service' in ((result.stdout or '')+(result.stderr or '')).lower():registered=False
        else:raise ValueError('无法核实系统时区服务是否注册，请检查系统权限。')
        legacy=False
        if not self.fixture and self.layout.label==Layout().label and platform.system()=='Darwin':
            from .component_inventory import Layout as ComponentsLayout, mac_snapshot, blocking
            legacy=blocking(mac_snapshot(ComponentsLayout(Path.home(),'Darwin'),os.getuid(),roles=['timezone']), 'timezone')
        pending=(root/'pending').exists()
        if values['baseline'] and not pending:
            base=values['baseline']
            if (type(base.get('format')) is not int or base.get('format')!=1 or type(base.get('owner_uid')) is not int or base['owner_uid']<0
                    or base.get('helper_sha256')!=hashes['worker'] or daemon_bytes(self.layout)!=self.read(self.layout.daemon)):
                raise ValueError('时区服务文件与安装记录不一致，请使用恢复入口或手动核对。')
            _zone(base.get('target'));_zone(base.get('original'))
        elif not pending and (any(hashes.values()) or registered):
            raise ValueError('存在不完整或未知的同名时区服务，未覆盖。')
        return {**values,'hashes':hashes,'registered':registered,'pending':pending,'legacy_registered':legacy}

    def execute(self,script):
        script=privileged_script(self.layout,script,self.worker())
        apple='do shell script '+json.dumps(script,ensure_ascii=False)+' with administrator privileges without altering line endings'
        result=self.runner(['/usr/bin/osascript','-e',apple],timeout=150)
        from .consent import raise_for_consent
        raise_for_consent(result, 'Darwin')


def system_timezone_service(store,reader,*,system=None,**kwargs):
    system=system or platform.system()
    if system=='Windows':
        from .timezone_windows import WindowsTimezoneService
        return WindowsTimezoneService(store,reader,**kwargs)
    return TimezoneService(store,reader,system=system,**kwargs)


class TimezoneService:
    def __init__(self,store,reader,*,system=None,io=None,uid=None):
        self.store,self.reader=store,reader
        self.system=system or platform.system();self.io=io or NativeTimezoneIO()
        self.uid=os.getuid() if uid is None and hasattr(os,'getuid') else uid if uid is not None else -1
        self.plans={}

    def status(self):
        if self.system!='Darwin':return {'state':'not_applicable','supported':False,'reason':'Windows 时区守护使用现有用户权限；此系统授权入口用于 macOS。'}
        try:
            value=self.io.inspect();base=value['baseline'];heartbeat=value['status']
            if value['pending']:
                state,reason='recovery_required','上次时区服务操作未完成，请先预览恢复方案。'
            elif value.get('legacy_registered'):
                state,reason='conflict','原版 local.tz-watchdog 正在运行，不能同时批准两个时区基线。先停用原版时区守护后再刷新；具体步骤见系统时区守护说明。'
            elif not base:
                state,reason='not_installed','尚未授权系统时区守护；确认后由 macOS 申请管理员授权。'
            elif base['owner_uid']!=self.uid:
                state,reason='conflict','系统时区守护由另一用户配置；请联系其本人或系统管理员。'
            elif not value['registered']:
                state,reason='unregistered','服务文件存在，但系统未确认注册。可预览重新安装。'
            elif heartbeat and (type(heartbeat.get('guard_policy')) is not int or heartbeat.get('guard_policy')!=2):
                state,reason='outdated','系统时区守护仍使用旧策略，不能确认已监测旧任务冲突；请预览更新并等待新心跳。'
            elif not heartbeat_current(base,heartbeat,self.io.clock(),fixture=self.io.fixture):
                state,reason='waiting','尚未收到当前基线的新心跳，请刷新；没有心跳不计为守护正常。'
            elif heartbeat.get('state')=='legacy_conflict':
                state,reason='conflict','后台检测到旧时区任务重新出现或登记读取失败，已暂停写入。请处理旧任务并复检。'
            elif heartbeat.get('state') in ('healthy','restored') and heartbeat.get('observed')==base['target']:
                state,reason='active','系统时区基线已读回，后台每 60 秒检查；写入失败会冷却并记录。'
            else:
                state,reason='attention','时区守护需处理：'+str(heartbeat.get('state','unknown'))+'。可查看记录并重新批准基线。'
            return {'supported':True,'state':state,'reason':reason,'target':base.get('target'),
                    'observed':heartbeat.get('observed'),'heartbeat_at':heartbeat.get('at_epoch'),
                    'installed':bool(base),'registered':value['registered'],'pending':value['pending'],
                    'intentionally_removed':not base and value.get('transaction',{}).get('owner_uid')==self.uid and (value.get('outcome',{}).get('state')=='rolled_back' or value.get('outcome',{}).get('state')=='committed' and value.get('transaction',{}).get('operation')=='remove'),
                    'original':base.get('original'),'release':base.get('release'),
                    'journal_path':str(self.io.layout.root),'owner':base.get('owner_uid')==self.uid,
                    'can_undo':not value['pending'] and value.get('transaction',{}).get('owner_uid')==self.uid
                               and value.get('outcome')=={'format':1,'nonce':value.get('transaction',{}).get('nonce'),'state':'committed'},
                    'needs_update':bool(base) and base.get('release')!=__release__}
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
            return {'supported':True,'state':'attention','reason':'时区服务状态或权限无法核实，未报告正常；请核对系统服务文件与日志。'}

    def prepare(self,report,*,remove=False,restore=False):
        if self.system!='Darwin':return self.status()
        if type(remove) is not bool or type(restore) is not bool:raise ValueError('时区服务选项无效')
        observed=_zone(current_region(self.reader())['timezone'])
        snapshot=self.io.inspect();snapshot['observed']=observed
        if snapshot['pending']:return {'state':'recovery_required','reason':'上次操作未完成，请先恢复时区服务。'}
        if snapshot.get('legacy_registered') and not remove:
            return {'state':'blocked','reason':'原版 local.tz-watchdog 正在运行。请先按系统时区守护说明停用旧任务，避免两个基线互相覆盖；原文件与账号资料保留。'}
        base=snapshot['baseline']
        if base and base['owner_uid']!=self.uid:return {'state':'blocked','reason':'时区守护属于另一用户，不覆盖其批准基线。'}
        settings=self.store.settings()
        if remove:
            if not base:return {'state':'guided','reason':'没有已安装的时区守护。'}
            target=base['target']
            effects=['申请一次 macOS 管理员授权，停止并移除 EnvScope 系统时区服务；保留日志与恢复备份。']
            effects.append('恢复安装前的系统时区：'+base['original'] if restore else '保留当前系统时区：'+observed)
        else:
            from .regions import region_finding, PARTIAL
            from .model import Status
            if (not SolutionPlans._current(report) or not settings.get('environment_confirmed')
                    or not settings.get('usage_country') or settings.get('usage_country') in PARTIAL
                    or region_finding([],settings).status==Status.FAIL
                    or report.get('environment',{}).get('fingerprint')!=fingerprint(settings)
                    or not any(f['id']=='target.region' and f['status']=='pass' for f in report.get('findings',[]))):
                return {'state':'retest_required','reason':'先确认实际地区和使用目标，并完成新的地区资格检测。'}
            selected=profile(settings.get('region_profile'),'Darwin')
            if not selected or settings.get('timezone')!=selected['timezone']:
                return {'state':'guided','reason':'请先在环境目标中选择明确的城市时区，再申请系统时区守护。'}
            target=_zone(selected['timezone'])
            effects=['申请一次 macOS 管理员授权；此设置影响整台 Mac 的所有用户。',
                     '将系统时区从 '+observed+' 配置为 '+target+'，写入后独立读回。',
                     '安装或更新每 60 秒运行的原生时区服务，守护程序与批准配置均由 root 持有。',
                     '每次修复先记录；至少间隔 5 分钟，24 小时最多尝试 3 次。中断或反复失败暂停并提示处理。',
                     '保留原时区、服务备份和本机事件日志，可停用并选择恢复安装前时区。']
        try:worker=self.io.worker()
        except (ValueError,OSError) as exc:return {'state':'guided','reason':str(exc)}
        script,receipt=render_transaction(self.io.layout,snapshot,worker,'remove' if remove else 'install',target,self.uid,restore)
        token=secrets.token_urlsafe(20)
        self.plans={token:{'deadline':time.monotonic()+90,'fingerprint':fingerprint(settings),
                           'snapshot':snapshot,'target':target,'remove':remove,'restore':restore,'worker':worker,
                           'script':script,'receipt':receipt}}
        return {'state':'planned','plan_id':token,'transaction_nonce':receipt['nonce'],'before_signature':_signature(snapshot),
                'effects':effects,'reason':'核对后确认；macOS 会在实际操作时申请系统授权。'}

    def apply(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if not plan or plan.get('recovery') or plan.get('undo') or time.monotonic()>plan['deadline'] or plan['fingerprint']!=fingerprint(self.store.settings()):
            return {'state':'retest_required','reason':'方案已过期或目标已改变，请重新预览。'}
        snapshot=self.io.inspect();snapshot['observed']=_zone(current_region(self.reader())['timezone'])
        if _stable(snapshot)!=_stable(plan['snapshot']) or self.io.worker()!=plan['worker']:
            return {'state':'retest_required','reason':'服务、系统时区或辅助程序在预览后发生变化，请重新预览。'}
        del self.plans[token]
        try:
            self.io.execute(plan['script'])
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            from .consent import operation_outcome
            return {'state':'partial','status':self.status(),'transaction_nonce':plan['receipt']['nonce'],
                    **operation_outcome(exc),'reason':str(exc)[:240]+' 现有备份和日志保留。'}
        status=self.status()
        completed=(not status.get('installed') and not status.get('registered') and not status.get('pending')
                   if plan['remove'] else status.get('installed') and status.get('registered') and status.get('target')==plan['target'] and not status.get('pending'))
        return {'state':'completed' if completed else 'partial','status':status,'needs_retest':True,'transaction_nonce':plan['receipt']['nonce'],
                'reason':'时区服务已移除，请复检系统时区。' if completed and plan['remove'] else
                         '时区服务已安装并注册；请刷新确认新心跳，再复检环境。' if completed else
                         '系统操作已返回，但实际状态尚未完整确认，请查看红色状态与恢复记录。'}

    def prepare_undo(self,expected_nonce=None):
        if self.system!='Darwin':return self.status()
        snapshot=self.io.inspect();snapshot['observed']=_zone(current_region(self.reader())['timezone'])
        receipt=snapshot['transaction']
        if snapshot['pending']:return {'state':'recovery_required','reason':'先恢复未完成的时区服务操作。'}
        if not receipt or receipt.get('owner_uid')!=self.uid:
            return {'state':'blocked','reason':'没有属于当前用户的可撤销事务。'}
        if expected_nonce is not None and receipt.get('nonce')!=expected_nonce:
            return {'state':'retest_required','reason':'时区服务已有后续操作，未覆盖新的基线。'}
        worker=self.io.worker()
        try:script=render_undo(self.io.layout,snapshot,worker)
        except ValueError as exc:return {'state':'guided','reason':str(exc)}
        token=secrets.token_urlsafe(20)
        self.plans={token:{'deadline':time.monotonic()+90,'undo':True,'snapshot':snapshot,'worker':worker,'script':script}}
        effects=['申请一次系统授权，撤销上次时区服务操作；此设置影响整台 Mac。',
                 '将系统时区恢复为上次操作前的 '+receipt['before']+'，读回后保留全部备份与事件日志。',
                 '恢复此前的服务文件、尝试次数和注册状态。']
        if receipt.get('previous_target'):
            effects.append('恢复后继续守护旧基线 '+receipt['previous_target']+'；若原时区与旧基线不同，后续巡检会按旧基线处理。')
        else:effects.append('此前未安装服务，恢复后不再自动保持时区。')
        return {'state':'planned','plan_id':token,'effects':effects,'reason':'只撤销最新且未变化的操作，不覆盖后续配置。'}

    def undo(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if not plan or not plan.get('undo') or time.monotonic()>plan['deadline']:
            return {'state':'retest_required','reason':'撤销方案已过期，请重新预览。'}
        snapshot=self.io.inspect();snapshot['observed']=_zone(current_region(self.reader())['timezone'])
        if _stable(snapshot)!=_stable(plan['snapshot']) or self.io.worker()!=plan['worker']:
            return {'state':'retest_required','reason':'服务或时区在预览后变化，未覆盖后续设置。'}
        del self.plans[token]
        try:self.io.execute(plan['script'])
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            from .consent import operation_outcome
            return {'state':'partial','reason':str(exc)[:240],'status':self.status(),**operation_outcome(exc)}
        completed=self._restored(self.io.inspect(),plan['snapshot']['transaction'])
        return {'state':'completed' if completed else 'partial','status':self.status(),'needs_retest':True,
                'reason':'已恢复原时区及此前的时区守护基线，请复检。' if completed else '撤销后的配置尚未完整读回，请保留恢复记录并复检。'}

    def _restored(self,snapshot,receipt):
        return (not snapshot['pending'] and snapshot['registered']==receipt['registered']
                and all(snapshot['hashes'].get(k)==receipt['hashes'].get(k) for k in ('worker','baseline.plist','daemon'))
                and current_region(self.reader())['timezone']==receipt['before'])

    def rollback_latest(self,nonce,confirmed=False,*,unchanged_signature=None):
        """Compensate a disclosed parent operation, never a later user's change."""
        if confirmed is not True:return {'state':'confirmation_required'}
        if self.system!='Darwin':return self.status()
        snapshot=self.io.inspect();snapshot['observed']=_zone(current_region(self.reader())['timezone'])
        receipt=snapshot['transaction']
        if receipt.get('nonce')!=nonce:
            if unchanged_signature and _signature(snapshot)==unchanged_signature:
                return {'state':'completed','reason':'时区服务方案尚未执行，原配置保持不变。'}
            return {'state':'retest_required','reason':'时区服务已有其他操作，未覆盖后续配置。'}
        if receipt.get('owner_uid')!=self.uid:return {'state':'blocked','reason':'事务属于另一用户。'}
        if snapshot['pending']:
            plan=self.prepare_recovery()
            return self.recover(plan['plan_id'],True) if plan.get('state')=='planned' else plan
        outcome=snapshot.get('outcome',{})
        if outcome.get('nonce')==nonce and outcome.get('state') in ('restored','rolled_back'):
            return {'state':'completed' if self._restored(snapshot,receipt) else 'partial',
                    'reason':'此事务已回滚；原配置读回不符时请核对后续系统变化。','needs_retest':True}
        plan=self.prepare_undo(nonce)
        return self.undo(plan['plan_id'],True) if plan.get('state')=='planned' else plan

    def prepare_recovery(self):
        if self.system!='Darwin':return self.status()
        snapshot=self.io.inspect()
        if not snapshot['pending']:return {'state':'guided','reason':'没有未完成的时区服务事务。'}
        receipt=snapshot['transaction'];before=_zone(receipt.get('before'))
        if receipt.get('owner_uid')!=self.uid:return {'state':'blocked','reason':'恢复记录属于另一用户，请由其本人或系统管理员处理。'}
        worker=self.io.worker();script=render_recovery(self.io.layout,snapshot,worker)
        token=secrets.token_urlsafe(20)
        self.plans={token:{'deadline':time.monotonic()+90,'recovery':True,'receipt':receipt,'script':script,'worker':worker}}
        return {'state':'planned','plan_id':token,'effects':['申请一次系统授权，停止当前时区服务并恢复上次保存的服务文件。',
                    '将系统时区恢复为事务开始前的 '+before+'；保留全部备份与事件日志。',
                    '恢复旧服务原来的注册状态；不会自动重新尝试失败的新方案。'],
                'reason':'恢复方案仅使用 root 持有且校验一致的备份；记录改变时停止。'}

    def recover(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if not plan or not plan.get('recovery') or time.monotonic()>plan['deadline']:
            return {'state':'retest_required','reason':'恢复方案已过期，请重新预览。'}
        current=self.io.inspect()
        if not current['pending'] or current['transaction']!=plan['receipt'] or self.io.worker()!=plan['worker']:
            return {'state':'retest_required','reason':'恢复现场已变化，请重新预览。'}
        del self.plans[token]
        try:self.io.execute(plan['script'])
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            from .consent import operation_outcome
            return {'state':'partial','reason':str(exc)[:240],'status':self.status(),**operation_outcome(exc)}
        status=self.status()
        completed=self._restored(self.io.inspect(),plan['receipt'])
        return {'state':'completed' if completed else 'partial','needs_retest':True,
                'status':status,'reason':'时区服务恢复操作已返回，请刷新心跳并重新检测环境。'}
