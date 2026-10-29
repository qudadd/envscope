import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.accounts import AccountManager, AccountError
from envscope.dmg_archive import DmgArchive, DiskImages, MARKER, _password, _tree
from envscope.operations import Operations
from envscope.state import StateStore

PASSWORD = 'dmg-fixture-password-123'


class FakeImages:
    """Filesystem fixture, never calls a system mount or reads real accounts."""
    def __init__(self, root):
        self.root, self.images, self.mounts = root, {}, {}
        self.fail_detach = self.fail_attach_after_mount = False

    def create(self, source, image, slot, password):
        key = ('image-'+str(len(self.images))).encode()
        data = self.root/key.decode()
        shutil.copytree(source, data, symlinks=True)
        self.images[key] = (data, password)
        image.write_bytes(key)

    def verify(self, image, password):
        data = self.images.get(image.read_bytes())
        if data is None or password != data[1]:
            raise AccountError('password or image invalid')

    def attach(self, image, mount, password):
        self.verify(image, password)
        shutil.copytree(self.images[image.read_bytes()][0], mount, dirs_exist_ok=True, symlinks=True)
        self.mounts[image] = mount
        if self.fail_attach_after_mount:
            raise AccountError('attach timed out after mounting')

    def detach(self, image, mount):
        if self.fail_detach:
            raise AccountError('device busy')
        if image in self.mounts:
            shutil.rmtree(self.mounts.pop(image))
            mount.mkdir()


class DmgTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manager = AccountManager(self.root/'state', self.root/'live')
        self.manager.accounts_dir.mkdir(parents=True)
        self.manager.data_dir.mkdir()
        (self.manager.state_dir/self.manager.current_filename).write_text('A')
        self.profile = self.manager.accounts_dir/'B'
        (self.profile/'nested/empty').mkdir(parents=True)
        (self.profile/'Local State').write_bytes(b'FIXTURE_DEVICE_B')
        (self.profile/'nested/session').write_bytes(b'FIXTURE_SESSION_B')
        self.disk = FakeImages(self.root)
        self.archive = DmgArchive(self.manager,self.root/'work',system='Darwin',disk=self.disk)
        self.file = self.root/'backup.dmg'

    def old_image(self, slot='C', metadata=None, password='old-pass'):
        source = self.root/'old-source';source.mkdir()
        (source/'state').write_bytes(b'OLD_FIXTURE')
        (source/MARKER).write_text(json.dumps(metadata or {'format':'claude-switcher-snapshot','version':1,'account':slot}))
        self.disk.create(source,self.file,slot,_password(password))
        return source

    def test_new_image_preserves_original_layout_and_full_data(self):
        original = _tree(self.profile)
        result = self.archive.export('B',str(self.file),PASSWORD)
        self.assertTrue(result['verified'])
        data = self.disk.images[self.file.read_bytes()][0]
        metadata = json.loads((data/MARKER).read_text())
        self.assertEqual(metadata['account'],'B')
        self.assertEqual(metadata['envscope']['files'],original)
        self.assertTrue((data/'Local State').exists())
        self.assertFalse((data/'data').exists())
        shutil.rmtree(self.profile)
        result = self.archive.import_archive(str(self.file),'B',PASSWORD)
        self.assertEqual(result['verification'],'image_checksum_and_file_manifest')
        self.assertEqual(_tree(self.profile),original)
        self.assertFalse((self.profile/MARKER).exists())
        self.assertFalse(self.archive.status()['pending'])
        self.assertFalse(self.disk.mounts)

    def test_legacy_eight_character_password_and_scope(self):
        self.old_image()
        result = self.archive.import_archive(str(self.file),'C','old-pass')
        self.assertEqual(result['verification'],'legacy_image_checksum_and_copy_readback')
        self.assertEqual((self.manager.accounts_dir/'C/state').read_bytes(),b'OLD_FIXTURE')

    def test_wrong_password_corruption_and_mismatched_slot_do_not_import(self):
        self.old_image()
        for slot,password in [('C','incorrect'),('D','old-pass')]:
            with self.assertRaises(AccountError):
                self.archive.import_archive(str(self.file),slot,password)
            self.assertFalse((self.manager.accounts_dir/slot).exists())
            self.assertFalse(self.archive.status()['pending'])
        self.file.write_bytes(b'broken')
        with self.assertRaises(AccountError):
            self.archive.import_archive(str(self.file),'C','old-pass')

    def test_active_occupied_and_custom_slots_rejected(self):
        self.old_image(slot='B')
        original = _tree(self.profile)
        with self.assertRaises(AccountError):
            self.archive.import_archive(str(self.file),'B','old-pass')
        for slot in ('A','custom'):
            with self.assertRaises(AccountError):
                self.archive.export(slot,str(self.root/'new.dmg'),PASSWORD)
        self.assertEqual(_tree(self.profile),original)

    def test_existing_file_is_never_replaced(self):
        self.file.write_bytes(b'EXISTING')
        with self.assertRaises(AccountError):
            self.archive.export('B',str(self.file),PASSWORD)
        self.assertEqual(self.file.read_bytes(),b'EXISTING')

    def test_publication_race_preserves_other_file_and_removes_partial(self):
        def collision(stage,target):
            target.write_bytes(b'OTHER_EXPORT')
            raise FileExistsError()
        with patch('envscope.dmg_archive.os.link',side_effect=collision):
            with self.assertRaises(FileExistsError):
                self.archive.export('B',str(self.file),PASSWORD)
        self.assertEqual(self.file.read_bytes(),b'OTHER_EXPORT')
        self.assertFalse(list(self.root.glob('*.part')))

    def test_failed_detach_preserves_work_and_explicit_cleanup_recovers(self):
        self.old_image()
        self.disk.fail_detach = True
        with self.assertRaisesRegex(AccountError,'暂存清理'):
            self.archive.import_archive(str(self.file),'C','old-pass')
        self.assertFalse((self.manager.accounts_dir/'C').exists())
        self.assertEqual(len(self.archive.status()['pending']),1)
        with self.assertRaisesRegex(AccountError,'上次遗留'):
            self.archive.import_archive(str(self.file),'C','old-pass')
        self.disk.fail_detach = False
        self.assertEqual(self.archive.cleanup()['state'],'completed')
        self.assertFalse(self.disk.mounts)
        self.assertFalse(self.archive.status()['pending'])

    def test_attach_timeout_after_mount_still_detaches_and_does_not_import(self):
        self.old_image()
        self.disk.fail_attach_after_mount = True
        with self.assertRaises(AccountError):
            self.archive.import_archive(str(self.file),'C','old-pass')
        self.assertFalse(self.disk.mounts)
        self.assertFalse(self.archive.status()['pending'])
        self.assertFalse((self.manager.accounts_dir/'C').exists())

    def test_tampered_new_manifest_rejected(self):
        self.archive.export('B',str(self.file),PASSWORD)
        data = self.disk.images[self.file.read_bytes()][0]
        (data/'Local State').write_bytes(b'CHANGED')
        shutil.rmtree(self.profile)
        with self.assertRaisesRegex(AccountError,'清单'):
            self.archive.import_archive(str(self.file),'B',PASSWORD)
        self.assertFalse(self.profile.exists())

    def test_bounds_and_reserved_profile_names(self):
        with patch('envscope.dmg_archive.LIMIT',1):
            with self.assertRaisesRegex(AccountError,'上限'):
                self.archive.export('B',str(self.file),PASSWORD)
        (self.profile/MARKER).write_text('user file')
        with self.assertRaisesRegex(AccountError,'保留名称'):
            self.archive.export('B',str(self.file),PASSWORD)
        self.assertEqual((self.profile/MARKER).read_text(),'user file')

    def test_password_line_injection_and_windows_no_execution(self):
        for password in ('short',PASSWORD+'\n',PASSWORD+'\0'):
            with self.assertRaises(ValueError):
                self.archive.export('B',str(self.file),password)
        self.archive.system = 'Windows'
        with self.assertRaisesRegex(AccountError,'macOS'):
            self.archive.export('B',str(self.file),PASSWORD)
        self.assertFalse(self.disk.images)

    def test_native_operations_require_real_boolean_and_bypass_legacy(self):
        operations=Operations(StateStore(memory=True),self.root,account_manager=self.manager,discoverer=lambda:[])
        operations.dmg_archives=self.archive
        for action,params in [('archive-export',{'slot':'B','file':str(self.file),'password':PASSWORD,'format':'dmg'}),
                              ('snapshot-export',{'account':'B','file':str(self.file),'password':PASSWORD}),('archive-cleanup',{})]:
            for confirm in (False,'true',1):
                self.assertEqual(operations.run(action,params,confirm)['state'],'confirmation_required')
        with patch.object(operations.legacy,'run',side_effect=AssertionError('No vendor execution')):
            result=operations.run('snapshot-export',{'account':'B','file':str(self.file),'password':PASSWORD},True)
            self.assertEqual(result['state'],'completed')


class HdiutilContractTests(unittest.TestCase):
    def test_stdin_only_and_output_redaction(self):
        disk=DiskImages()
        with patch('envscope.dmg_archive.subprocess.run',return_value=Mock(returncode=1,stdout=b'PASSWORD_SECRET',stderr=b'PASSWORD_SECRET')) as run:
            with self.assertRaises(AccountError) as error:
                disk.create(Path('/fixture'),Path('/fixture.dmg'),'B',_password(PASSWORD))
            self.assertNotIn('PASSWORD_SECRET',str(error.exception))
            self.assertNotIn(PASSWORD,str(run.call_args.args))
            self.assertEqual(run.call_args.kwargs['input'],_password(PASSWORD))
            self.assertEqual(run.call_args.args[0][0],'/usr/bin/hdiutil')

    def test_unencrypted_unknown_and_string_truth_rejected(self):
        for value in ({},{'encrypted':False},{'encrypted':'true'}):
            with patch.object(DiskImages,'run',return_value=value):
                with self.assertRaises(AccountError):DiskImages().encrypted(Path('/fixture'))

    def test_unrelated_mount_is_never_detached(self):
        disk=DiskImages()
        with patch.object(disk,'attached',return_value=[{'system-entities':[{'dev-entry':'/dev/disk9','mount-point':'/Volumes/user'}]}]), patch.object(disk,'run') as run:
            with self.assertRaises(AccountError):disk.detach(Path('/owned.dmg'),Path('/approved'))
            run.assert_not_called()

    def test_exact_image_device_is_detached_and_read_back(self):
        disk=DiskImages()
        entries=[{'system-entities':[{'dev-entry':'/dev/disk9'},{'dev-entry':'/dev/disk9s1','mount-point':str(Path('/approved'))}]}]
        with patch.object(disk,'attached',side_effect=[entries,[]]),patch.object(disk,'run') as run:
            disk.detach(Path('/owned.dmg'),Path('/approved'))
            run.assert_called_once_with(['detach','/dev/disk9'],timeout=30)


if __name__=='__main__':
    unittest.main()
