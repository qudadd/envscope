"""Privileged one-shot network operations; Python remains an ordinary user."""
import hashlib
import os
from pathlib import Path,PurePosixPath
import plistlib
import secrets
import shlex
import stat
import subprocess
import tempfile

from . import __release__
from .accounts import _safe_chain
from .system_network import validate_snapshot
from .timezone_service import Layout,NativeTimezoneIO,_header,bundle_worker,privileged_script


class MacNetworkIO:
    def __init__(self,*,runner=None,layout=None,worker=None,fixture=False):
        self.layout=layout or Layout(PurePosixPath('/Library/PrivilegedHelperTools/io.qudadd.envscope.network'),
                                     PurePosixPath('/Library/LaunchDaemons/io.qudadd.envscope.network.unused.plist'),
                                     'io.qudadd.envscope.network')
        self.runner=runner or subprocess.run
        self.worker=worker or (lambda:bundle_worker(component='network'))
        self.fixture=fixture

    def snapshot(self):
        helper=self.worker()
        result=self.runner([helper['path'],'--snapshot'],capture_output=True,timeout=12)
        if result.returncode or len(result.stdout)>2*1024**2:
            raise ValueError('未能读取完整的系统网络服务，请在系统网络设置核对。')
        try:value=plistlib.loads(result.stdout)
        except (ValueError,TypeError):raise ValueError('系统网络读取结果无效。') from None
        value=validate_snapshot(value)
        if value.get('release')!=__release__ or value.get('fixture') is not self.fixture:
            raise ValueError('系统网络辅助程序范围或版本不符。')
        return value

    def status(self):
        root=Path(self.layout.root);_safe_chain(root)
        if root.exists():
            info=root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                raise ValueError('系统网络恢复目录的权限异常，请保留现场并由管理员核对。')
        raw=NativeTimezoneIO().read(root/'latest.plist',2*1024**2)
        if raw is None:return {'state':'not_configured','id':''}
        try:value=plistlib.loads(raw)
        except ValueError:raise ValueError('系统网络恢复记录无法读取，请保留备份。') from None
        if (not isinstance(value,dict) or type(value.get('format')) is not int or value['format']!=1
                or not isinstance(value.get('id'),str) or len(value['id'])!=32
                or any(c not in '0123456789abcdef' for c in value['id'])
                or value.get('fixture') is not self.fixture
                or value.get('state') not in ('prepared','partial','committed','rolled_back','restored')):
            raise ValueError('系统网络恢复记录格式或范围不符，请保留备份。')
        validate_snapshot({'format':1,'owner':value.get('owner'),'adapters':value.get('adapters')})
        return value

    def script(self,action,payload_path,payload_sha,worker):
        if action not in ('apply','restore'):raise ValueError('不支持的系统网络操作')
        for value in (payload_sha,worker['sha256']):
            if len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError('系统网络操作摘要无效')
        nonce=secrets.token_hex(12)
        body=_header(self.layout)+f'NET_INPUT="$ROOT/.input-{nonce}.plist"\nNET_WORKER="$ROOT/.worker-{nonce}"\n'
        body+='''trap '/bin/rm -f "$NET_INPUT" "$NET_WORKER"' EXIT
trap 'exit 130' INT TERM HUP
'''
        body+=f'/bin/cp {shlex.quote(worker["path"])} "$NET_WORKER"\n/bin/chmod 755 "$NET_WORKER"\n'
        body+=f'safe "$NET_WORKER" && [ "$(digest "$NET_WORKER")" = {shlex.quote(worker["sha256"])} ] || exit 79\n'
        body+=f'/bin/cp {shlex.quote(str(payload_path))} "$NET_INPUT"\n/bin/chmod 600 "$NET_INPUT"\n'
        body+=f'safe "$NET_INPUT" && [ "$(digest "$NET_INPUT")" = {shlex.quote(payload_sha)} ] || exit 79\n'
        body+=f'"$NET_WORKER" --{action} < "$NET_INPUT"\n'
        return privileged_script(self.layout,body,worker)

    def execute(self,action,payload):
        import json
        data=plistlib.dumps(payload,sort_keys=True)
        if len(data)>2*1024**2:raise ValueError('网络操作数据超出审核范围。')
        with tempfile.TemporaryDirectory(prefix='envscope-network-plan-') as temporary:
            path=Path(temporary).resolve()/'plan.private.bin'
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            script=self.script(action,path,hashlib.sha256(data).hexdigest(),self.worker())
            apple='do shell script '+json.dumps(script,ensure_ascii=False)+' with administrator privileges without altering line endings'
            result=self.runner(['/usr/bin/osascript','-e',apple],capture_output=True,timeout=150)
            if result.returncode:
                raise ValueError('系统授权取消或网络修改未完成。请刷新恢复记录；未将命令返回当作修复成功。')
