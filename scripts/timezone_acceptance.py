"""Real root launchd lifecycle against compile-time fixture paths only.

Never calls the real systemsetup setter. The production worker is separately
built and checked for fixture=false by desktop packaging.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shlex
import subprocess
import tempfile
import time
import uuid

from envscope.timezone_service import Layout,NativeTimezoneIO,render_transaction,render_recovery,render_undo,privileged_script
from scripts.build_timezone_worker import build


def sudo(script,check=True):
    value=subprocess.run(['/usr/bin/sudo','-n','/bin/sh'],input=script,text=True,capture_output=True,timeout=150)
    if check and value.returncode:
        raise RuntimeError('Owned timezone fixture command failed: '+value.stderr[-1200:])
    return value


def wait_status(io,condition,timeout=90):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=io.inspect()
        if condition(value):return value
        time.sleep(1)
    raise AssertionError('Fixture service did not produce the required status')


def main():
    if (platform.system()!='Darwin' or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('ENVSCOPE_TIMEZONE_ACCEPTANCE')!='1'):
        raise SystemExit('This root-service fixture runs only in explicitly opted-in macOS CI')
    nonce=uuid.uuid4().hex[:12]
    root=Path('/Library/PrivilegedHelperTools')/('io.qudadd.envscope.timezone.ci-'+nonce)
    label='io.qudadd.envscope.timezone.ci-'+nonce
    layout=Layout(root,Path('/Library/LaunchDaemons')/(label+'.plist'),label)
    actual_before=str(Path('/etc/localtime').resolve())
    output=Path('artifacts/timezone-acceptance');output.mkdir(parents=True,exist_ok=True)
    proof={'platform':platform.system(),'architecture':platform.machine(),'fixture':True,
           'real_timezone_changed':False,'real_accounts_used':False,'production_service_installed':False}
    with tempfile.TemporaryDirectory(prefix='envscope-tz-build-') as directory:
        directory=Path(directory).resolve()
        header=directory/'fixture.h'
        header.write_text('\n'.join('#define '+key+' '+json.dumps(str(value)) for key,value in {
            'ENVSCOPE_TZ_ROOT':root,'ENVSCOPE_TZ_LOCALTIME':root/'localtime',
            'ENVSCOPE_TZ_ZONES':root/'zones','ENVSCOPE_TZ_SETTER':root/'setter'}.items())+'\n#define ENVSCOPE_TZ_FIXTURE 1\n')
        binary=build(directory/'native',header)/'timezone-helper'
        worker={'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        io=NativeTimezoneIO(layout=layout,worker=lambda:worker,fixture=True)
        phases=[]
        try:
            quoted=shlex.quote(str(root))
            setup='''set -eu
root=@ROOT@
if [ ! -d /Library/PrivilegedHelperTools ]; then /bin/mkdir /Library/PrivilegedHelperTools; /bin/chmod 755 /Library/PrivilegedHelperTools; fi
[ ! -e "$root" ] && [ ! -L "$root" ]
/bin/mkdir "$root"
/bin/chmod 755 "$root"
/bin/chmod -N "$root"
/bin/mkdir -p "$root/zones/Asia" "$root/zones/America" "$root/zones/Europe"
/usr/bin/printf fixture > "$root/zones/Asia/Shanghai"
/usr/bin/printf fixture > "$root/zones/America/New_York"
/usr/bin/printf fixture > "$root/zones/Europe/London"
/bin/chmod -R go+rX "$root/zones"
/bin/ln -s "$root/zones/Asia/Shanghai" "$root/localtime"
'''.replace('@ROOT@',quoted)
            setter='''#!/bin/sh
set -eu
ROOT=@ROOT@
[ "$1" = -settimezone ]
case "$2" in Asia/Shanghai|America/New_York|Europe/London) ;; *) exit 2;; esac
[ ! -e "$ROOT/fail-setter" ] || exit 1
/bin/ln -s "$ROOT/zones/$2" "$ROOT/localtime.next"
/bin/mv -f "$ROOT/localtime.next" "$ROOT/localtime"
'''.replace('@ROOT@',quoted)
            setup+='/usr/bin/printf %s '+shlex.quote(__import__('base64').b64encode(setter.encode()).decode())+' | /usr/bin/base64 -D > "$root/setter"\n/bin/chmod 755 "$root/setter"\n'
            sudo(setup)
            def snapshot():
                value=io.inspect();value['observed']=str((root/'localtime').resolve()).split('/zones/',1)[1];return value
            def execute(script,check=True):return sudo(privileged_script(layout,script,worker),check)
            hold=privileged_script(layout,'/usr/bin/touch '+shlex.quote(str(root/'lease-held'))+'\n/bin/sleep 4\n',worker)
            process=subprocess.Popen(['/usr/bin/sudo','-n','/bin/sh'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            process.stdin.write(hold);process.stdin.close();process.stdin=None
            deadline=time.monotonic()+10
            while not (root/'lease-held').exists() and time.monotonic()<deadline:time.sleep(.05)
            assert (root/'lease-held').exists()
            assert execute('/usr/bin/printf concurrent',False).returncode!=0
            _,stderr=process.communicate(timeout=10)
            assert process.returncode==0,stderr
            proof['exclusive_lifecycle_lock']=True
            script,_=render_transaction(layout,snapshot(),worker,'install','America/New_York',os.getuid())
            execute(script);phases.append('installed')
            first=wait_status(io,lambda x:x['status'].get('state')=='healthy' and x['status'].get('initial') is False)
            assert first['status']['fixture'] is True
            # A later timestamp must come from the system's StartInterval, not a
            # manually requested worker invocation.
            stamp=first['status']['at_epoch']
            second=wait_status(io,lambda x:x['status'].get('at_epoch',0)>stamp+20,timeout=90)
            proof['automatic_heartbeats']=2;phases.append('periodic_heartbeat')
            # Age only the fixture attempt history, then simulate drift.
            sudo('/bin/rm -f '+shlex.quote(str(root/'state.plist'))+'\n/bin/ln -sfn '+shlex.quote(str(root/'zones/Asia/Shanghai'))+' '+shlex.quote(str(root/'localtime')))
            changed=wait_status(io,lambda x:x['status'].get('state')=='restored',timeout=90)
            assert changed['status']['observed']=='America/New_York';phases.append('drift_repaired')
            # Reconfigure a root service, preserving its original timezone.
            script,_=render_transaction(layout,snapshot(),worker,'install','Europe/London',os.getuid())
            execute(script)
            updated=wait_status(io,lambda x:x['status'].get('initial') is False and x['status'].get('target')=='Europe/London')
            assert updated['baseline']['original']=='Asia/Shanghai';phases.append('updated')
            # Restore exact previous files and attempt history, then update again.
            undo_snapshot=snapshot();prior_hashes=undo_snapshot['transaction']['hashes']
            execute(render_undo(layout,undo_snapshot,worker))
            undone=io.inspect()
            assert undone['baseline']['target']=='America/New_York' and undone['hashes']==prior_hashes
            assert undone['outcome']['state']=='restored' and not undone['pending']
            assert str((root/'localtime').resolve()).endswith('/America/New_York');phases.append('committed_update_undone')
            script,_=render_transaction(layout,snapshot(),worker,'install','Europe/London',os.getuid())
            execute(script)
            # A failed initial apply must restore old files, old timezone and
            # original registration; the failed candidate remains in a backup.
            sudo('/usr/bin/touch '+shlex.quote(str(root/'fail-setter')))
            script,_=render_transaction(layout,snapshot(),worker,'install','America/New_York',os.getuid())
            result=execute(script,False);assert result.returncode!=0
            sudo('/bin/rm -f '+shlex.quote(str(root/'fail-setter')))
            rolled=io.inspect();assert not rolled['pending'] and rolled['baseline']['target']=='Europe/London' and rolled['registered']
            assert str((root/'localtime').resolve()).endswith('/Europe/London');phases.append('failed_update_rolled_back')
            # Interrupt after the complete receipt and backups but before any
            # mutation. Explicit recovery verifies and restores that snapshot.
            script,receipt=render_transaction(layout,snapshot(),worker,'install','America/New_York',os.getuid())
            head=script.split('rollback() {',1)[0]
            execute(head)
            pending=io.inspect();assert pending['pending']
            execute(render_recovery(layout,pending,worker))
            assert not io.inspect()['pending'];phases.append('interruption_recovered')
            # Remove the service and restore its first pre-install value.
            script,_=render_transaction(layout,snapshot(),worker,'remove',owner_uid=os.getuid(),restore=True)
            execute(script)
            ended=io.inspect();assert not ended['registered'] and not ended['baseline'] and not ended['pending']
            assert str((root/'localtime').resolve()).endswith('/Asia/Shanghai');phases.append('removed_and_restored')
            execute(render_undo(layout,snapshot(),worker))
            assert io.inspect()['baseline']['target']=='Europe/London' and io.inspect()['registered']
            phases.append('uninstall_undone')
            script,_=render_transaction(layout,snapshot(),worker,'remove',owner_uid=os.getuid(),restore=True)
            execute(script)
            assert not io.inspect()['registered'] and str((root/'localtime').resolve()).endswith('/Asia/Shanghai')
            logs='\n'.join(p.read_text() for p in root.glob('*.private.jsonl'))
            (output/'fixture-events.txt').write_text(logs)
            proof.update(state='passed',phases=phases,root_owned_worker=True,configuration_readback=True,
                         drift_repair=True,update=True,rollback=True,recovery=True,uninstall=True,committed_undo=True,uninstall_undo=True)
        finally:
            # Only this UUID-owned service and exact checked root are removed.
            assert root.parent==Path('/Library/PrivilegedHelperTools') and root.name=='io.qudadd.envscope.timezone.ci-'+nonce
            sudo('/bin/launchctl bootout '+shlex.quote('system/'+label)+' >/dev/null 2>&1 || true\n/bin/rm -f '+shlex.quote(str(layout.daemon))+'\n/bin/rm -rf '+shlex.quote(str(root)),False)
            proof['real_timezone_changed']=str(Path('/etc/localtime').resolve())!=actual_before
            assert not proof['real_timezone_changed']
            assert not root.exists() and not layout.daemon.exists()
            proof['fixture_removed']=True
            (output/'result.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
