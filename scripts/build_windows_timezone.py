"""Compile the closed Windows worker; building never registers or changes OS state."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

from envscope import __release__


def build(destination=None, *, fixture=False):
    if platform.system() != 'Windows':
        raise RuntimeError('Windows compiler required')
    root = Path(__file__).resolve().parents[1]
    folder = Path(destination or root / 'build/native-timezone-windows').resolve()
    folder.mkdir(parents=True, exist_ok=True)
    binary = folder / 'timezone-helper.exe'
    source = root / 'native/timezone_windows.c'
    environment = {key.upper(): value for key, value in os.environ.items()}
    compiler = os.environ.get('CC') or shutil.which('cl.exe') or shutil.which('gcc.exe')
    if not compiler and os.environ.get('RTOOLS45_HOME'):
        compiler = next((str(p) for p in Path(os.environ['RTOOLS45_HOME']).glob('*w64*/bin/gcc.exe') if p.is_file()), None)
    if not compiler:
        finder = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        if finder.is_file():
            setup = subprocess.check_output([str(finder), '-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-find', 'VC/Auxiliary/Build/vcvars64.bat'], text=True).strip()
            if setup and Path(setup).is_file():
                result = subprocess.check_output(['cmd.exe', '/d', '/s', '/c', '""' + setup + '" >nul && set"'], text=True, errors='replace')
                environment.update((key.upper(), value) for key, value in (line.split('=', 1) for line in result.splitlines() if '=' in line and not line.startswith('=')))
                compiler = shutil.which('cl.exe', path=environment.get('PATH'))
    if not compiler:
        raise RuntimeError('Install MSVC C++ Build Tools or put a Windows GCC compiler on PATH')
    environment['PATH'] = str(Path(compiler).parent) + os.pathsep + environment.get('PATH', '')
    defines = ['ENVSCOPE_RELEASE="' + __release__ + '"', 'ENVSCOPE_FIXTURE=' + str(int(fixture))]
    if Path(compiler).name.lower() == 'cl.exe':
        command = [compiler, '/nologo', '/O2', '/W3', '/WX', '/MT', '/D_CRT_SECURE_NO_WARNINGS'] + ['/D' + d for d in defines]
        command += [str(source), '/Fo:' + str(folder / 'worker.obj'), '/Fe:' + str(binary), '/link', 'advapi32.lib', 'shell32.lib', 'bcrypt.lib']
    else:
        command = [compiler, '-municode', '-static', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation'] + ['-D' + d for d in defines]
        command += [str(source), '-o', str(binary), '-ladvapi32', '-lshell32', '-lbcrypt']
    result = subprocess.run(command, cwd=folder, env=environment, capture_output=True, text=True, errors='replace')
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    version = json.loads(subprocess.check_output([str(binary), '--version']))
    if version != {'format': 1, 'release': __release__, 'fixture': fixture}:
        raise ValueError('Unexpected worker identity')
    metadata = {**version, 'architecture': platform.machine(), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    (folder / 'timezone-helper.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return folder


if __name__ == '__main__':
    print(build())
