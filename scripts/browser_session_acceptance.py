"""Actual parent-exit / detached cleanup with inert processes and temp data only."""
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

import psutil

from envscope import __release__
from envscope.browser_sessions import process_alive


def run_acceptance(executable=None, *, native_proof=None):
    if platform.system() not in ('Windows','Darwin'):
        return {'state':'not_applicable','scope':'Windows / macOS owned-process acceptance only'}
    if executable:
        # Never send an unknown test flag to an older executable: it could
        # launch the ordinary app. Standard --desktop-smoke proves support first.
        assert native_proof and native_proof.get('browser_session_fixture') is True
        assert native_proof.get('native_browser_registry') is True and native_proof.get('release')==__release__
        command = [str(executable),'--browser-session-fixture']
    else:
        command = [sys.executable,'-m','envscope.desktop','--browser-session-fixture']
    with tempfile.TemporaryDirectory(prefix='envscope-browser-acceptance-') as temporary:
        root = Path(temporary).resolve()
        parent = subprocess.Popen(command+[str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        owned = {}
        try:
            out,err = parent.communicate(timeout=30)
            assert parent.returncode==0,err.decode('utf-8',errors='replace')[-2000:]
            owned = json.loads((root/'fixture-result.private.json').read_text())
            assert parent.poll()==0 and process_alive(owned['parent_pid'],owned['parent_birth']) is False
            status_path=root/'.envscope/browser-cleanup-worker.private.json'
            startup_deadline=time.monotonic()+5
            while not status_path.exists() and time.monotonic()<startup_deadline:
                time.sleep(.05)
            from envscope.browser_sessions import _read
            status=_read(status_path)
            owned.update(worker_actual_pid=status['pid'],worker_actual_birth=status['birth'])
            assert process_alive(owned['worker_actual_pid'],owned['worker_actual_birth']) is True, 'Cleanup must outlive its parent'
            directory = root/'.envscope/browser-sessions'/owned['token']
            deadline = time.monotonic()+25
            while time.monotonic()<deadline and (directory.exists() or process_alive(owned['worker_actual_pid'],owned['worker_actual_birth']) is not False):
                time.sleep(.2)
            assert not directory.exists(), 'Owned browser profile was not recovered after parent exit'
            assert process_alive(owned['sleeper_pid'],owned['sleeper_birth']) is False
            assert process_alive(owned['worker_actual_pid'],owned['worker_actual_birth']) is False
            events = b''.join(p.read_bytes() for p in (root/'.envscope/browser-cleanup-events').glob('*'))
            assert b'cleanup_started' in events and b'removed' in events and b'stopped' in events
            assert b'OWNED_BROWSER_SESSION_FIXTURE_ONLY' not in events
            return {'state':'passed','release':__release__,'platform':platform.system(),
                    'parent_exited_first':True,'detached_worker_survived':True,'owned_process_exit_observed':True,
                    'profile_removed':True,'worker_stopped':True,'metadata_only_events':True,
                    'frozen':bool(executable),'real_browser_launched':False,'real_profile_used':False,'network_probes':False}
        except BaseException:
            from envscope.browser_sessions import SessionStore,profile_running
            store=SessionStore(root/'.envscope/browser-sessions')
            diagnostic={'owned_processes':owned,'inventory':store.inspect(),'worker':store.worker_status()}
            if diagnostic['worker'].get('state')=='running':
                owned.setdefault('worker_actual_pid',diagnostic['worker']['pid'])
                owned.setdefault('worker_actual_birth',diagnostic['worker']['birth'])
            if owned.get('token') and (store.root/owned['token']).exists():
                diagnostic['session']=store.read(owned['token'])
                diagnostic['profile_observed_running']=profile_running(store.root/owned['token']/'profile',platform.system())
            diagnostic['events']=[json.loads(row) for p in (root/'.envscope/browser-cleanup-events').glob('*') for row in p.read_text().splitlines()]
            output=Path('artifacts/browser-session-acceptance');output.mkdir(parents=True,exist_ok=True)
            (output/'failure.private.json').write_text(json.dumps(diagnostic,indent=2),encoding='utf-8')
            print(json.dumps({'failure_inventory':diagnostic['inventory'],'failure_worker':diagnostic['worker'],'last_states':[v['state'] for v in diagnostic['events'][-5:]]}))
            raise
        finally:
            if parent.poll() is None:
                parent.terminate();parent.wait(timeout=10)
            for role in ('sleeper','worker_actual','worker'):
                pid,birth = owned.get(role+'_pid'),owned.get(role+'_birth')
                if pid and birth and process_alive(pid,birth) is True:
                    # Only the exact process created above, never a browser or
                    # a reused PID. No name-based broad termination.
                    process=psutil.Process(pid)
                    commands=process.cmdline()
                    expected=role=='sleeper' or any(str(root) in arg for arg in commands)
                    if abs(process.create_time()-birth)<.01 and expected:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except psutil.NoSuchProcess: pass


def main():
    result = run_acceptance()
    output = Path('artifacts/browser-session-acceptance');output.mkdir(parents=True,exist_ok=True)
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':main()
