"""Install the real built archive via fixture metadata, then test its native UI."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from envscope.state import StateStore
from envscope import __release__
from envscope.updates import AppUpdates, API, asset_name


def main():
    archive = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('dist') / asset_name()
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    tag = 'v99.0.0-alpha.1'  # Synthetic discovery version; not a published release.
    prefix = 'https://github.com/qudadd/envscope/releases/download/' + tag + '/'
    metadata = [{'tag_name': tag, 'draft': False, 'prerelease': True, 'assets': [
        {'name': archive.name, 'state': 'uploaded', 'size': archive.stat().st_size, 'digest': 'sha256:' + digest, 'browser_download_url': prefix + archive.name},
        {'name': 'SHA256SUMS', 'state': 'uploaded', 'browser_download_url': prefix + 'SHA256SUMS'}]}]
    def fixture(url, limit, destination=None):
        if url.startswith(API):
            return json.dumps(metadata).encode()
        if '/commits/' in url:
            return b'{}'
        if url.endswith('/SHA256SUMS'):
            return (digest + '  ' + archive.name + '\n').encode()
        if url == prefix + archive.name and destination:
            shutil.copyfile(archive, destination)
            return destination.stat().st_size
        raise AssertionError('No real update network requests allowed')
    with tempfile.TemporaryDirectory(prefix='envscope-update-fixture-') as directory:
        store = StateStore(Path(directory) / 'state')
        updater = AppUpdates(store, fixture)
        assert updater.check()['state'] == 'available'
        assert updater.install(tag)['state'] == 'confirmation_required'
        assert updater.install(tag, True)['state'] == 'ready'
        executable = updater.installed()
        output = Path(directory) / 'native.json'
        result = subprocess.run([str(executable), '--desktop-smoke', str(output)], capture_output=True,
                                timeout=180, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        assert result.returncode == 0, 'Installed binary failed to start its isolated test'
        native = json.loads(output.read_text())
        assert not native['errors'] and native['native_window'] and native['tray'] and native['quit']
        assert native['release'] == __release__, 'Installed archive release does not match the source'
        evidence = {'archive': archive.name, 'sha256': digest, 'metadata': 'offline-fixture', 'installed_archive': True, 'native': native, 'real_update_network': False, 'real_user_data_changed': False}
        path = Path('artifacts/update-package-smoke.json')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
        print(json.dumps(evidence))


if __name__ == '__main__':
    main()
