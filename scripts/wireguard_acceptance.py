"""Windows CI only: inspect one owned, inert SCM service using production APIs.

Never calls WireGuard, installs a driver or creates a network interface. The
fixture binary accepts /tunnelservice only to exercise command-line parsing.
"""
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import uuid

from envscope.wireguard import PREFIX, WireGuardReader, select_service


def run(command):
    value = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if value.returncode:
        raise RuntimeError('owned service fixture command failed: '+Path(command[0]).name+' '+str(value.returncode))
    return value


def main():
    if (platform.system() != 'Windows' or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('ENVSCOPE_SERVICE_ACCEPTANCE') != '1'):
        raise SystemExit('Owned SCM fixture is restricted to explicitly enabled Windows CI')
    output = Path('artifacts/wireguard-service'); output.mkdir(parents=True, exist_ok=True)
    result = {'passed': False, 'scope': 'actual Windows SCM and process identity, one inert owned fixture; no VPN/network changes',
              'network_changes': False, 'fixture_removed': False}
    marker = 'EnvScopeFixture' + uuid.uuid4().hex
    name = PREFIX + marker
    windows = Path(os.environ['SystemRoot'])/'System32'
    sc, shell = str(windows/'sc.exe'), str(windows/'WindowsPowerShell/v1.0/powershell.exe')
    try:
        with tempfile.TemporaryDirectory(prefix='EnvScope-service-fixture-') as folder:
            root = Path(folder).resolve(); source = root/'OwnedFixture.cs'; binary = root/'wireguard.exe'
            source.write_text('''using System.ServiceProcess;
public sealed class OwnedFixture : ServiceBase {
 public OwnedFixture() { ServiceName = "'''+name+'''"; CanStop = true; AutoLog = false; }
 protected override void OnStart(string[] args) { }
 protected override void OnStop() { }
 public static void Main(string[] args) { ServiceBase.Run(new OwnedFixture()); }
}''', encoding='utf-8')
            compile_script = root/'compile.ps1'
            compile_script.write_text("$ErrorActionPreference='Stop'\nAdd-Type -Path '"+str(source).replace("'", "''")+
                "' -ReferencedAssemblies System.ServiceProcess -OutputType ConsoleApplication -OutputAssembly '"+
                str(binary).replace("'", "''")+"'\n", encoding='utf-8')
            run([shell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(compile_script)])
            command = '"'+str(binary)+'" /tunnelservice "'+str(root/(marker+'.conf'))+'"'
            reader = WireGuardReader(names=lambda: [name], binaries=[str(binary)])
            created = False
            try:
                run([sc, 'create', name, 'type=', 'own', 'start=', 'demand', 'binPath=', command, 'obj=', 'LocalSystem'])
                created = True
                before = reader.collect()
                assert select_service(before, name)[0] == 'offline', before
                run([sc, 'start', name])
                deadline = time.monotonic()+20
                while True:
                    live = reader.collect(); state, row = select_service(live, name)
                    if state == 'healthy': break
                    if time.monotonic() >= deadline: raise AssertionError(live)
                    time.sleep(.2)
                result['live_identity'] = {'service': name, 'pid': row['pid'], 'created': row['created'], 'sha256': row['sha256']}
                run([sc, 'stop', name])
                deadline = time.monotonic()+20
                while True:
                    stopped = reader.collect()
                    if select_service(stopped, name)[0] == 'offline': break
                    if time.monotonic() >= deadline: raise AssertionError(stopped)
                    time.sleep(.2)
                result['checks'] = ['registered-but-stopped-is-failure', 'SCM-own-process-PID-and-installed-path',
                                    'real-CommandLineToArgvW', 'process-creation-time-readback', 'binary-digest-readback',
                                    'stopped-is-no-longer-healthy', 'no-config-or-key-file-read']
                assert not (root/(marker+'.conf')).exists(), 'Fixture must not create or read VPN keys'
                result['passed'] = True
            finally:
                if created:
                    # Fixed, unique name created in this invocation only.
                    subprocess.run([sc, 'stop', name], capture_output=True, timeout=20)
                    run([sc, 'delete', name])
                    deadline = time.monotonic()+15
                    while True:
                        query = subprocess.run([sc, 'query', name], capture_output=True, timeout=10)
                        if query.returncode == 1060:
                            result['fixture_removed'] = True; break
                        if time.monotonic() >= deadline: raise AssertionError('Owned service was not removed')
                        time.sleep(.2)
    finally:
        (output/'result.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    assert result['passed'] and result['fixture_removed'], result
    print(json.dumps(result))


if __name__ == '__main__': main()
