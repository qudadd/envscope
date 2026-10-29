"""Actual macOS hdiutil checks, using only generated disposable account data."""
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

from envscope import __release__
from envscope.accounts import AccountManager, AccountError
from envscope.dmg_archive import DmgArchive, DiskImages, MARKER, _tree, _password


def exercise(root):
    assert platform.system() == 'Darwin'
    root = Path(root).resolve()
    manager = AccountManager(root/'state',root/'live')
    manager.accounts_dir.mkdir(parents=True)
    manager.data_dir.mkdir()
    (manager.state_dir/manager.current_filename).write_text('A')
    profile = manager.accounts_dir/'B'
    (profile/'nested/empty').mkdir(parents=True)
    (profile/'Local State').write_bytes(b'FIXTURE_DEVICE_B')
    (profile/'nested/session').write_bytes(b'FIXTURE_OAUTH_B')
    (profile/'中文资料').write_bytes(b'FIXTURE_UNICODE')
    expected = _tree(profile)
    archive = DmgArchive(manager,root/'work')
    disk = DiskImages()
    filename = root/'new.dmg'
    password = 'native-dmg-fixture-123'
    exported = archive.export('B',str(filename),password)
    assert exported['encrypted'] and exported['verified']
    assert b'FIXTURE_OAUTH_B' not in filename.read_bytes()
    shutil.rmtree(profile)
    imported = archive.import_archive(str(filename),'B',password)
    assert imported['verification'] == 'image_checksum_and_file_manifest'
    assert _tree(profile) == expected
    # A fixture matching the pinned upstream writer, not execution of that writer.
    source = root/'old-root';source.mkdir()
    (source/'legacy-state').write_bytes(b'FIXTURE_LEGACY')
    (source/MARKER).write_text(json.dumps({'format':'claude-switcher-snapshot','version':1,'account':'C','created':'2026-01-01 00:00:00'}))
    legacy = root/'old.dmg'
    disk.create(source,legacy,'C',_password('old-pass'))
    old = archive.import_archive(str(legacy),'C','old-pass')
    assert old['verification'] == 'legacy_image_checksum_and_copy_readback'
    assert (manager.accounts_dir/'C/legacy-state').read_bytes() == b'FIXTURE_LEGACY'
    before = _tree(manager.accounts_dir)
    for file,slot,secret in [(legacy,'D','old-pass'),(legacy,'C','old-pass'),(legacy,'D','incorrect-fixture')]:
        try:
            archive.import_archive(str(file),slot,secret)
        except AccountError:
            pass
        else:
            raise AssertionError('Invalid import was accepted')
    assert _tree(manager.accounts_dir) == before
    raw = root/'unencrypted.dmg'
    disk.run(['create','-srcfolder',source,raw],timeout=120)
    try:
        archive.import_archive(str(raw),'D','old-pass')
    except AccountError:
        pass
    else:
        raise AssertionError('Unencrypted image was accepted')
    # Read the new image with the same macOS primitive used by the original
    # importer. The marker and profile must be directly at the volume root.
    mount = root/'legacy-reader';mount.mkdir()
    try:
        disk.attach(filename,mount,_password(password))
        marker = json.loads((mount/MARKER).read_text())
        assert marker['format'] == 'claude-switcher-snapshot' and marker['version'] == 1 and marker['account'] == 'B'
        assert (mount/'Local State').read_bytes() == b'FIXTURE_DEVICE_B'
        assert _tree(mount,image=True) == expected
    finally:
        disk.detach(filename,mount)
    assert not archive.status()['pending']
    attached = disk.run(['info','-plist'],plist=True)['images']
    assert not [x for x in attached if str(x.get('image-path','')).startswith(str(root)+'/')]
    logs=''.join(p.read_text() for p in (root/'work/events').glob('*.private.jsonl'))
    assert password not in logs and 'old-pass' not in logs and 'FIXTURE_OAUTH' not in logs
    return {'native_dmg_roundtrip':True,'original_root_layout':True,'legacy_eight_character_password':True,
            'wrong_password_rejected':True,'mismatch_and_occupied_rejected':True,'unencrypted_rejected':True,
            'mounts_removed':True,'plaintext_workspaces_removed':True,'no_password_in_logs':True,
            'real_accounts_used':False,'vendor_scripts_executed':False}


def main():
    output=Path('artifacts/dmg-acceptance');output.mkdir(parents=True,exist_ok=True)
    result={'platform':platform.system(),'architecture':platform.machine(),'release':__release__}
    if platform.system()!='Darwin':
        result.update(state='not_applicable',reason='Original DMG compatibility is macOS only')
    else:
        # Retain the installed Apple manual as a local development artifact only.
        manual=subprocess.run(['/usr/bin/man','hdiutil'],capture_output=True,timeout=15,env={'PATH':'/usr/bin:/bin','MANWIDTH':'120'})
        (output/'hdiutil-manual.txt').write_bytes(manual.stdout)
        with tempfile.TemporaryDirectory(prefix='envscope-dmg-acceptance-') as temporary:
            result.update(exercise(Path(temporary)),state='passed')
    (output/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':
    main()
