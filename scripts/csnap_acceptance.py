"""Independent .NET/Python CSNAP001 exchange on disposable fixtures only."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

from envscope.accounts import AccountManager
from envscope.csnap_archive import CsnapArchive


def main():
    output = Path('artifacts/csnap-acceptance'); output.mkdir(parents=True, exist_ok=True)
    if platform.system() != 'Windows':
        result = {'state':'not_applicable','scope':'Independent .NET exchange runs on Windows; portable vectors run on every OS.'}
    else:
        shell = shutil.which('pwsh') or shutil.which('powershell.exe')
        assert shell, 'A .NET PowerShell host is required for independent exchange'
        script = Path(__file__).with_name('csnap_crypto_oracle.ps1').resolve()
        with tempfile.TemporaryDirectory(prefix='envscope-csnap-oracle-') as directory:
            root = Path(directory).resolve()
            manager = AccountManager(root/'state', root/'live')
            manager.accounts_dir.mkdir(parents=True)
            manager.data_dir.mkdir()
            (manager.state_dir/manager.current_filename).write_text('A')
            profile = manager.accounts_dir/'B'; profile.mkdir()
            (profile/'fixture.txt').write_bytes(b'INDEPENDENT_DOTNET_FIXTURE')
            archive = CsnapArchive(manager, root/'work')
            candidate = root/'python.csnap'
            archive.export('B', str(candidate), 'fixture8')
            def oracle(mode, path):
                value = subprocess.run([shell,'-NoProfile','-NonInteractive','-File',str(script),mode,str(path)],
                                       capture_output=True, text=True, encoding='utf-8-sig', timeout=60)
                assert value.returncode == 0, 'Independent .NET oracle failed: '+value.stderr[-2000:]
                return json.loads(value.stdout)
            independent = oracle('-Candidate', candidate)
            assert independent == {'authenticated':True,'root_layout':True,'slot':'B','payload_verified':True}
            generated = root/'dotnet.csnap'
            assert oracle('-GenerateArchive', generated)['generated'] is True
            imported = archive.import_archive(str(generated),'C','x')
            assert imported['verified'] is True
            assert (manager.accounts_dir/'C/fixture.txt').read_bytes() == b'INDEPENDENT_DOTNET_FIXTURE'
            assert (manager.accounts_dir/'C/nested/empty').is_dir()
            assert not list((root/'work').iterdir())
            result = {'state':'passed','scope':'Self-authored .NET crypto and ZipArchive versus Python on fixture volumes',
                      'python_to_dotnet':True,'dotnet_to_python':True,'legacy_short_password':True,
                      'empty_directory_preserved':True,'vendor_executed':False,'real_account_or_network_changed':False,
                      'python_archive_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),
                      'dotnet_archive_sha256':hashlib.sha256(generated.read_bytes()).hexdigest()}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
