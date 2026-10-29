"""Build the native macOS worker; no service installation or system writes."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from envscope import __release__


def build(destination=None, fixture_header=None):
    if platform.system()!='Darwin':
        raise RuntimeError('The timezone worker is built only on macOS')
    root=Path(__file__).resolve().parents[1]
    folder=Path(destination or root/'build/native-timezone').resolve();folder.mkdir(parents=True,exist_ok=True)
    binary=folder/'timezone-helper'
    command=['/usr/bin/xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-O2',
             '-mmacosx-version-min=12.0','-DENVSCOPE_RELEASE="'+__release__+'"']
    if fixture_header:command+=['-include',str(Path(fixture_header).resolve())]
    command += [str(root/'native/timezone_worker.c'),'-framework','CoreFoundation','-o',str(binary)]
    subprocess.run(command,check=True,capture_output=True)
    subprocess.run(['/usr/bin/codesign','--force','--sign','-','--identifier','io.qudadd.envscope.timezone.worker',str(binary)],check=True,capture_output=True)
    version=json.loads(subprocess.check_output([str(binary),'--version']))
    assert version=={'format':1,'release':__release__,'fixture':bool(fixture_header)}
    value={**version,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'architecture':platform.machine()}
    (folder/'timezone-helper.json').write_text(json.dumps(value,indent=2),encoding='utf-8')
    return folder


if __name__=='__main__':
    print(build())
