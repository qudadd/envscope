"""Fixed launchd retirement through the separately bundled native transaction.

Only the reviewed native helper is executed as root. Its inputs are hash-bound
data; legacy scripts are not used as an installer, parser or recovery program.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import stat
import subprocess
import tempfile

from .accounts import _safe_chain
from .component_inventory import Layout, mac_snapshot, read_regular
from .timezone_service import bundle_worker


def clean(value):
    if isinstance(value, dict): return {k: clean(v) for k, v in value.items() if v is not None}
    if isinstance(value, list): return [clean(v) for v in value]
    return value


class MacComponents:
    def __init__(self, home, *, layout=None, runner=None, helper=None, jobs=None, uid=None):
        self.layout = layout or Layout(home, 'Darwin'); self.fixture = self.layout.fixture
        self.runner = runner or subprocess.run; self.uid = os.getuid() if uid is None else uid
        self.helper = helper or (lambda: bundle_worker(component='components')); self.jobs = jobs

    def snapshot(self): return mac_snapshot(self.layout, self.uid, jobs=self.jobs, runner=self.runner)

    def status(self):
        root = self.layout.root; _safe_chain(root)
        if root.exists():
            info = root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('旧组件恢复目录权限无法核实')
        data = read_regular(root/'latest.plist', owner=0, limit=1024*1024)
        if data is None: return {'state': 'not_configured', 'id': ''}
        value = plistlib.loads(data)
        if (not isinstance(value, dict) or value.get('format') != 1 or value.get('fixture') is not self.fixture
                or not re.fullmatch('[a-f0-9]{32}', str(value.get('id', '')))
                or value.get('state') not in ('prepared', 'partial', 'committed', 'restored', 'rolled_back')):
            raise ValueError('旧组件恢复记录格式不符')
        return value

    def execute(self, action, payload):
        if action not in ('retire', 'restore', 'retire-files', 'restore-files') or payload.get('actor') != str(self.uid): raise ValueError('组件操作用户不一致')
        worker = self.helper()
        if not re.fullmatch('[a-f0-9]{64}', str(worker.get('sha256', ''))): raise ValueError('组件辅助程序摘要未核实')
        raw = plistlib.dumps(clean(payload), sort_keys=True)
        with tempfile.TemporaryDirectory(prefix='envscope-components-plan-') as folder:
            path = Path(folder).resolve()/'plan.private.plist'; path.write_bytes(raw); path.chmod(0o600)
            # The root-owned stage and digest check follow the existing native
            # helper protocol. No user-writable script path is executed as root.
            # components-helper has its own lock and fixed operation interface;
            # unlike the timezone worker it does not execute a shell lifecycle.
            root = shlex.quote(str(self.layout.root)); nonce = os.urandom(12).hex()
            code = '''set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
umask 077
[ "$(/usr/bin/id -u)" = 0 ] || exit 77
safe() {
 [ ! -L "$1" ] && [ -e "$1" ] || return 1
 [ "$(/usr/bin/stat -f %u "$1")" = 0 ] || return 1
 m=$(/usr/bin/stat -f %Lp "$1");case "$m" in ''|*[!0-7]*) return 1;; esac
 [ $((0$m & 022)) -eq 0 ] || return 1
}
'''+f'ROOT={root}\nPARENT=$(/usr/bin/dirname "$ROOT")\n'
            code += '''if [ ! -e "$PARENT" ] && [ ! -L "$PARENT" ]; then
 safe "$(/usr/bin/dirname "$PARENT")" || exit 79
 /bin/mkdir "$PARENT"; /bin/chmod 755 "$PARENT"; /bin/chmod -N "$PARENT"
fi
safe "$PARENT" || exit 79
if [ ! -e "$ROOT" ] && [ ! -L "$ROOT" ]; then /bin/mkdir "$ROOT"; /bin/chmod 755 "$ROOT"; /bin/chmod -N "$ROOT"; fi
safe "$ROOT" || exit 79
'''
            # Staging is outside the managed journal. A corrupt ACL on an old
            # journal directory must not permit a swap of the root executable.
            code += 'safe /private/var/root || exit 79\n'
            code += f'STAGE=/private/var/root/.envscope-components-stage-{nonce}\n/bin/mkdir "$STAGE"\n/bin/chmod 700 "$STAGE"\n/bin/chmod -N "$STAGE"\n'
            code += '''trap '/bin/rm -f "$STAGE/helper" "$STAGE/plan.plist"; /bin/rmdir "$STAGE"' EXIT
trap 'exit 130' INT TERM HUP
'''
            code += '/bin/cp '+shlex.quote(worker['path'])+' "$STAGE/helper"\n/bin/chmod 500 "$STAGE/helper"\n'
            code += '/bin/cp '+shlex.quote(str(path))+' "$STAGE/plan.plist"\n/bin/chmod 600 "$STAGE/plan.plist"\n'
            code += 'safe "$STAGE/helper" && [ "$(/usr/bin/shasum -a 256 "$STAGE/helper" | /usr/bin/awk \'{print $1}\')" = '+shlex.quote(worker['sha256'])+' ] || exit 79\n'
            code += f'/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C "$STAGE/helper" --{action} "$STAGE/plan.plist" {shlex.quote(hashlib.sha256(raw).hexdigest())} {shlex.quote(str(self.uid))}\n'
            apple = 'do shell script '+json.dumps(code, ensure_ascii=False)+' with administrator privileges without altering line endings'
            result = self.runner(['/usr/bin/osascript', '-e', apple], capture_output=True, timeout=150)
            if result.returncode: raise ValueError('系统授权取消或旧组件操作未完全完成，请刷新并核对恢复记录')
