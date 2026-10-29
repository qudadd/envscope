"""Build the native macOS worker; no service installation or system writes."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from envscope import __release__


def build(destination=None, fixture_header=None, *, component='timezone'):
    if component not in ('timezone','network'):raise ValueError('Unknown native component')
    if platform.system()!='Darwin':
        raise RuntimeError('The timezone worker is built only on macOS')
    root=Path(__file__).resolve().parents[1]
    folder=Path(destination or root/('build/native-'+component)).resolve();folder.mkdir(parents=True,exist_ok=True)
    binary=folder/(component+'-helper')
    command=['/usr/bin/xcrun','clang','-std=c11','-Wall','-Wextra','-Werror','-O2',
             '-mmacosx-version-min=12.0','-DENVSCOPE_RELEASE="'+__release__+'"']
    if fixture_header:command+=['-include',str(Path(fixture_header).resolve())]
    command += [str(root/('native/'+component+'_worker.c')),'-framework','CoreFoundation']
    if component=='network':command+=['-framework','SystemConfiguration']
    command+=['-o',str(binary)]
    try:subprocess.run(command,check=True,capture_output=True)
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stderr.decode('utf-8',errors='replace'))
        raise
    subprocess.run(['/usr/bin/codesign','--force','--sign','-','--identifier','io.qudadd.envscope.'+component+'.worker',str(binary)],check=True,capture_output=True)
    version=json.loads(subprocess.check_output([str(binary),'--version']))
    assert version=={'format':1,'release':__release__,'fixture':bool(fixture_header)}
    value={**version,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'architecture':platform.machine()}
    (folder/(component+'-helper.json')).write_text(json.dumps(value,indent=2),encoding='utf-8')
    return folder


if __name__=='__main__':
    print(build())
