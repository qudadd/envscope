"""Real pinned Mihomo API, temporary fixture only; no TUN, DNS or traffic proxy.

Downloads a checksum-verified official test binary into ignored artifacts. The
core is not bundled with EnvScope and never uses the user's real configuration.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time
from urllib.request import urlopen
import zipfile

from envscope.local_controller import from_config
from envscope.model import make_report
from envscope.policy import Policy
from envscope.routing import Routing, FILES
from scripts.environment_fixtures import fixture
from tests.test_routing import setup_fixture

VERSION = 'v1.19.33'
ASSETS = {
    ('Windows', 'x64'): ('mihomo-windows-amd64-compatible-v1.19.33.zip', '7aaf636a4f2172dcd8ec34ac4f52797b059195e5afd6409508c963e545f8864d'),
    ('Darwin', 'x64'): ('mihomo-darwin-amd64-compatible-v1.19.33.gz', 'eefe967b74312f70b64efa0dfa54929d00c7af8e94416e1b12df09863a40f35b'),
    ('Darwin', 'arm64'): ('mihomo-darwin-arm64-v1.19.33.gz', '060b64b0f2c9a310831db0fe4adb2878de67bfa606c311813c1f13966aa504b6'),
}


def binary():
    arch = {'amd64': 'x64', 'x86_64': 'x64', 'aarch64': 'arm64'}.get(platform.machine().lower(), platform.machine().lower())
    name, sha = ASSETS[(platform.system(), arch)]
    folder = Path('artifacts/core-fixture') / VERSION / (platform.system() + '-' + arch)
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / name
    if not archive.exists():
        with urlopen('https://github.com/MetaCubeX/mihomo/releases/download/' + VERSION + '/' + name, timeout=40) as response:
            payload = response.read(40000001)
        if len(payload) > 40000000 or hashlib.sha256(payload).hexdigest() != sha:
            raise ValueError('official test core archive did not match pinned checksum')
        archive.write_bytes(payload)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != sha:
        raise ValueError('cached test archive checksum mismatch')
    executable = folder / ('mihomo.exe' if platform.system() == 'Windows' else 'mihomo')
    if name.endswith('.zip'):
        with zipfile.ZipFile(archive) as packed:
            members = [i for i in packed.infolist() if i.filename.endswith('.exe')]
            if len(members) != 1 or members[0].file_size > 100000000:
                raise ValueError('unrecognized official test archive')
            executable.write_bytes(packed.read(members[0]))
    else:
        with gzip.open(archive, 'rb') as stream:
            payload = stream.read(100000001)
        if len(payload) > 100000000: raise ValueError('oversized binary')
        executable.write_bytes(payload)
    executable.chmod(0o700)
    return executable.resolve(), sha


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--binary', type=Path)
    args = parser.parse_args()
    executable, archive_hash = (args.binary.resolve(), 'caller-supplied-test-binary') if args.binary else binary()
    with tempfile.TemporaryDirectory(prefix='envscope-core-fixture-') as temp:
        home = Path(temp).resolve(); system = platform.system()
        store, directory, _, _ = setup_fixture(home, system)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
        control = f'external-controller: 127.0.0.1:{port}\n'
        if system == 'Darwin':
            # Exercise actual AF_UNIX on both macOS architectures.
            control = 'external-controller-unix: ' + str(home / 'core.sock') + '\n'
        raw = ('''mode: rule
log-level: silent
port: 0
socks-port: 0
mixed-port: 0
redir-port: 0
tproxy-port: 0
allow-lan: false
ipv6: false
geodata-mode: false
geo-auto-update: false
secret: fixture-only-secret
tun: {enable: false}
dns: {enable: false}
profile: {store-selected: false, store-fake-ip: false}
proxies:
- {name: node, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: fixture-only, udp: true}
proxy-groups:
- {name: Claude, type: select, proxies: [node]}
rules:
- MATCH,DIRECT
''' + control).encode()
        config = directory / FILES['runtime']; config.write_bytes(raw)
        with (home / 'core.private.log').open('wb') as log:
            process = subprocess.Popen([str(executable), '-d', str(directory), '-f', str(config)], stdout=log, stderr=log,
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            try:
                route = Routing(store, home, system, {})
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None: raise RuntimeError('temporary core exited before API became available')
                    options = route.options()
                    if options.get('groups') == ['Claude']: break
                    if time.monotonic() > deadline: raise RuntimeError('temporary core was not ready: ' + options.get('reason', 'unknown'))
                    time.sleep(0.2)
                report = make_report(fixture(home, store.settings(), system), Policy(), 'one-click-desktop', store.settings())
                plan = route.prepare(report)
                if plan['state'] != 'planned': raise AssertionError(plan)
                applied = route.apply(plan['plan_id'], report, True)
                if applied['state'] != 'completed': raise AssertionError(applied)
                undo = route.undo_prepare(); result = route.undo(undo['plan_id'], True)
                if result['state'] != 'rolled_back' or config.read_bytes() != raw: raise AssertionError(result)
                proof = {'core': VERSION, 'archive_sha256': archive_hash, 'platform': system, 'machine': platform.machine(),
                         'transport': 'unix-socket' if system == 'Darwin' else 'loopback-http',
                         'native_rule_load': True, 'runtime_16_rules_verified': True, 'original_runtime_restored': True,
                         'fixture_only': True, 'tun_dns_and_proxy_listeners_disabled': True}
            finally:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
    output = Path('artifacts/routing-core'); output.mkdir(parents=True, exist_ok=True)
    (output / 'result.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
    print(json.dumps(proof))


if __name__ == '__main__': main()
