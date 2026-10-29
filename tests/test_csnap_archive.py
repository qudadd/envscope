import base64
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from envscope.accounts import AccountManager, AccountError, RecoveryRequired, _manifest
from envscope.csnap_archive import (CsnapArchive, MAGIC, MARKER, _encrypt, _decrypt, _pack,
                                    _unpack, _password, _zip_directory_guard)
from envscope.operations import Operations
from envscope.state import StateStore

PASSWORD = 'fixture8'


class CsnapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manager = AccountManager(self.root/'state', self.root/'live', current_filename='current.txt',
                                      stop_app=Mock(side_effect=AssertionError('No process action')),
                                      launch_app=Mock(side_effect=AssertionError('No process action')))
        self.manager.accounts_dir.mkdir(parents=True)
        self.manager.data_dir.mkdir()
        (self.manager.state_dir/'current.txt').write_text('A')
        self.profile = self.manager.accounts_dir/'B'
        (self.profile/'nested/empty').mkdir(parents=True)
        (self.profile/'Local State').write_bytes(b'FIXTURE_DEVICE_B')
        (self.profile/'nested/session').write_bytes(b'FIXTURE_SESSION_B')
        self.archive = CsnapArchive(self.manager, self.root/'work')
        self.file = self.root/'backup.csnap'

    def legacy(self, entries=None, metadata=None, password=PASSWORD):
        plain = self.root/'legacy.zip'
        with zipfile.ZipFile(plain, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            if metadata is not False:
                marker = {'format':'claude-switcher-snapshot','version':1,'account':'C'} if metadata is None else metadata
                z.writestr(MARKER, json.dumps(marker))
            for name, value in entries or [('fixture', b'OLD_FIXTURE')]:
                if isinstance(name, str):
                    item = zipfile.ZipInfo('placeholder')
                    # ZipInfo normalizes backslashes on Windows. Override the
                    # writer field to test hostile bytes, not a normalized name.
                    item.filename = name
                    item.orig_filename = name
                    z.writestr(item, value)
                else:
                    z.writestr(name, value)
        _encrypt(plain, self.file, password)

    def test_independent_dotnet_vectors_encrypt_and_decrypt(self):
        oracle = json.loads((Path(__file__).parent/'fixtures/csnap_crypto.json').read_text(encoding='utf-8'))
        self.assertEqual(len(oracle['vectors']), 6)
        for n, vector in enumerate(oracle['vectors']):
            with self.subTest(n=n):
                plain, encrypted, decoded = (self.root/f'{n}-{part}' for part in ('plain','encrypted','decoded'))
                plain.write_bytes(base64.b64decode(vector['plaintext_base64']))
                expected = base64.b64decode(vector['encrypted_base64'])
                with patch('envscope.csnap_archive.secrets.token_bytes', side_effect=[bytes(range(16)), bytes(range(16,32))]):
                    _encrypt(plain, encrypted, vector['password'])
                self.assertEqual(encrypted.read_bytes(), expected)
                _decrypt(encrypted, decoded, vector['password'])
                self.assertEqual(decoded.read_bytes(), plain.read_bytes())

    def test_root_layout_full_roundtrip_and_unicode(self):
        (self.profile/'中文 🔒.txt').write_bytes(bytes(range(256))*10241)
        before = _manifest(self.profile)
        result = self.archive.export('b', str(self.file), '公开测试🔒1234')
        self.assertTrue(result['verified'])
        self.assertEqual(self.file.read_bytes()[:8], MAGIC)
        decoded = self.root/'decoded.zip'
        _decrypt(self.file, decoded, '公开测试🔒1234')
        with zipfile.ZipFile(decoded) as z:
            self.assertIn('Local State', z.namelist())
            self.assertNotIn('data/Local State', z.namelist())
            self.assertEqual(json.loads(z.read(MARKER))['account'], 'B')
        shutil.rmtree(self.profile)
        self.archive.import_archive(str(self.file), 'B', '公开测试🔒1234')
        self.assertEqual(_manifest(self.profile), before)
        self.assertFalse((self.profile/MARKER).exists())
        self.assertFalse(list((self.root/'work').iterdir()))

    def test_legacy_short_password_bom_metadata_and_no_manifest(self):
        plain = self.root/'old.zip'
        with zipfile.ZipFile(plain, 'w') as z:
            z.writestr(MARKER, b'\xef\xbb\xbf'+b'{"format":"claude-switcher-snapshot","version":1,"account":"C"}')
            z.writestr('state', b'OLD_FIXTURE')
        _encrypt(plain, self.file, 'x')
        result = self.archive.import_archive(str(self.file), 'C', 'x')
        self.assertTrue(result['verified'])
        self.assertEqual((self.manager.accounts_dir/'C/state').read_bytes(), b'OLD_FIXTURE')

    def test_wrong_password_and_all_authenticated_regions_before_plaintext(self):
        self.legacy()
        original = self.file.read_bytes()
        destination = self.root/'plaintext.zip'
        with self.assertRaises(AccountError):
            _decrypt(self.file, destination, 'wrong')
        self.assertFalse(destination.exists())
        for offset in (0, 8, 24, 40, 71, 72, len(original)-1):
            with self.subTest(offset=offset):
                changed = bytearray(original); changed[offset] ^= 1
                self.file.write_bytes(changed)
                with self.assertRaises(AccountError):
                    _decrypt(self.file, destination, PASSWORD)
                self.assertFalse(destination.exists())
        self.assertFalse((self.manager.accounts_dir/'C').exists())

    def test_truncation_and_bad_lengths(self):
        self.legacy(); original = self.file.read_bytes()
        for length in (0, 8, 71, 72, 73, 87, len(original)-1, len(original)-16):
            with self.subTest(length=length):
                self.file.write_bytes(original[:length])
                with self.assertRaises(AccountError):
                    self.archive.import_archive(str(self.file), 'C', PASSWORD)
                self.assertFalse((self.manager.accounts_dir/'C').exists())

    def test_mutation_between_authentication_and_decryption_never_imports(self):
        self.legacy()
        from envscope import csnap_archive
        comparison = csnap_archive.hmac.compare_digest
        called = False
        def mutate(a, b):
            nonlocal called
            if not called:
                called = True
                value = bytearray(self.file.read_bytes()); value[72] ^= 1
                self.file.write_bytes(value)
            return comparison(a, b)
        destination = self.root/'plaintext.zip'
        with patch.object(csnap_archive.hmac,'compare_digest',side_effect=mutate):
            with self.assertRaises(AccountError): _decrypt(self.file,destination,PASSWORD)
        self.assertFalse(destination.exists())

    def test_existing_plaintext_destination_preserved(self):
        self.legacy()
        destination = self.root/'plaintext.zip'; destination.write_bytes(b'KEEP')
        with self.assertRaises(FileExistsError): _decrypt(self.file,destination,PASSWORD)
        self.assertEqual(destination.read_bytes(),b'KEEP')

    def test_small_zip64_container_import(self):
        self.legacy()
        plain = self.root/'legacy.zip'
        value = plain.read_bytes()
        eocd = value[-22:]
        _, _, _, _, count, length, start, _ = struct.unpack('<4s4H2LH',eocd)
        prefix = value[:-22]
        record = struct.pack('<4sQ2H2L4Q',b'PK\x06\x06',44,45,45,0,0,count,count,length,start)
        locator = struct.pack('<4sLQL',b'PK\x06\x07',0,len(prefix),1)
        sentinel = struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,0xffff,0xffff,0xffffffff,0xffffffff,0)
        plain.write_bytes(prefix+record+locator+sentinel)
        self.file.unlink(); _encrypt(plain,self.file,PASSWORD)
        self.archive.import_archive(str(self.file),'C',PASSWORD)
        self.assertEqual((self.manager.accounts_dir/'C/fixture').read_bytes(),b'OLD_FIXTURE')

    def test_file_dialog_selects_csnap_without_sending_password(self):
        operations = Operations(StateStore(self.root/'settings'),self.root,account_manager=self.manager)
        operations.desktop_runtime = Mock()
        operations.desktop_runtime.window.create_file_dialog.return_value = str(self.file)
        with patch.dict('sys.modules',{'webview':Mock(SAVE_DIALOG='save',OPEN_DIALOG='open')}):
            result = operations.run('archive-choose-file',{'format':'csnap','mode':'export'})
        self.assertEqual(result['file'],str(self.file))
        call = operations.desktop_runtime.window.create_file_dialog.call_args
        self.assertEqual(call.kwargs['file_types'],('Account archive (*.csnap)',))
        self.assertEqual(call.kwargs['save_filename'],'Claude-backup.csnap')

    def test_strict_confirmation_operation_and_no_credential_persistence(self):
        operations = Operations(StateStore(self.root/'settings'), self.root, account_manager=self.manager)
        params = {'slot':'B','file':str(self.file),'password':PASSWORD,'format':'csnap'}
        for confirm in (None, False, 1, 'true'):
            self.assertEqual(operations.run('archive-export', params, confirm)['state'], 'confirmation_required')
            self.assertFalse(self.file.exists())
        self.assertEqual(operations.run('archive-export', params, True)['state'], 'completed')
        for path in operations.store.root.rglob('*'):
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes())

    def test_active_occupied_pending_and_dynamic_slots_rejected_before_decrypt(self):
        self.legacy()
        for slot in ('A','B','work'):
            with self.subTest(slot=slot), patch('envscope.csnap_archive._decrypt', side_effect=AssertionError('Preflight first')):
                with self.assertRaises(AccountError):
                    self.archive.import_archive(str(self.file), slot, PASSWORD)
        (self.manager.accounts_dir/'C.previous').mkdir()
        with patch('envscope.csnap_archive._decrypt', side_effect=AssertionError('Preflight first')):
            with self.assertRaises(RecoveryRequired):
                self.archive.import_archive(str(self.file), 'C', PASSWORD)
        self.assertTrue((self.manager.accounts_dir/'C.previous').is_dir())

    def test_fresh_final_preflight_preserves_concurrent_account(self):
        self.legacy()
        from envscope import csnap_archive
        original = csnap_archive._unpack
        def occupy(*args):
            original(*args)
            target = self.manager.accounts_dir/'C'; target.mkdir(); (target/'existing').write_bytes(b'KEEP')
        with patch.object(csnap_archive, '_unpack', side_effect=occupy):
            with self.assertRaises(AccountError):
                self.archive.import_archive(str(self.file), 'C', PASSWORD)
        self.assertEqual((self.manager.accounts_dir/'C/existing').read_bytes(), b'KEEP')

    def test_source_and_destination_not_overwritten_and_no_partial_publication(self):
        self.file.write_bytes(b'KEEP')
        with self.assertRaises(ValueError): self.archive.export('B', str(self.file), PASSWORD)
        self.assertEqual(self.file.read_bytes(), b'KEEP')
        self.file.unlink()
        def concurrent(source, target):
            target.write_bytes(b'CONCURRENT')
            raise FileExistsError()
        with patch('envscope.csnap_archive.os.link', side_effect=concurrent):
            with self.assertRaises(FileExistsError): self.archive.export('B', str(self.file), PASSWORD)
        self.assertEqual(self.file.read_bytes(), b'CONCURRENT')
        self.assertFalse(list(self.root.glob('*.part')))

    def test_export_rejects_reserved_marker_and_managed_destination(self):
        (self.profile/MARKER).write_bytes(b'MUST_NOT_BE_LOST')
        with self.assertRaises(AccountError): self.archive.export('B', str(self.file), PASSWORD)
        self.assertEqual((self.profile/MARKER).read_bytes(), b'MUST_NOT_BE_LOST')
        with self.assertRaises(AccountError): self.archive.export('B', str(self.manager.state_dir/'bad.csnap'), PASSWORD)
        self.assertFalse(self.file.exists())

    def test_old_profile_timestamp_does_not_drop_file(self):
        os.utime(self.profile/'Local State',(0,0))
        self.archive.export('B',str(self.file),PASSWORD)
        shutil.rmtree(self.profile)
        self.archive.import_archive(str(self.file),'B',PASSWORD)
        self.assertEqual((self.profile/'Local State').read_bytes(),b'FIXTURE_DEVICE_B')

    def test_password_utf16_contract_and_invalid_input(self):
        self.assertEqual(_password('🔒'*4, exporting=True), ('🔒'*4).encode())
        for value in (None, 12, '', 'short', '\ud800', 'a'*1025):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError): _password(value, exporting=True)

    def test_zip_path_marker_types_and_directory_conflicts(self):
        bad_entries = [('../escape',b'x'),('/absolute',b'x'),('C:/escape',b'x'),('a\\b',b'x'),('a//b',b'x'),
                       ('a/./b',b'x'),('NUL.txt',b'x'),('a.',b'x'),('a /b',b'x'),('a:stream',b'x')]
        for n, entry in enumerate(bad_entries):
            with self.subTest(entry=entry[0]):
                self.file.unlink(missing_ok=True)
                self.legacy([entry])
                with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)
                self.assertFalse((self.manager.accounts_dir/'C').exists())
        for entries in ([('a',b'x'),('a/b',b'y')], [('a/file',b'x'),('A/other',b'y')], [('same',b'x'),('SAME',b'y')]):
            self.file.unlink(); self.legacy(entries)
            with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)

    def test_marker_schema_slot_and_size(self):
        for metadata in (False, {}, [], {'format':'claude-switcher-snapshot','version':True,'account':'C'},
                         {'format':'claude-switcher-snapshot','version':1,'account':'B'},
                         {'format':'claude-switcher-snapshot','version':1,'account':'C','padding':'x'*16384}):
            with self.subTest(metadata_type=type(metadata).__name__):
                self.file.unlink(missing_ok=True); self.legacy(metadata=metadata)
                with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)
        self.assertFalse((self.manager.accounts_dir/'C').exists())

    def test_symlink_zip_entry_and_hardlinked_source_rejected(self):
        link = zipfile.ZipInfo('symlink'); link.create_system = 3; link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.legacy([(link,b'../outside')])
        with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)
        other = self.root/'hardlink.csnap'; os.link(self.file,other)
        with self.assertRaises(AccountError): self.archive.import_archive(str(other),'C',PASSWORD)

    def test_zip_and_encrypted_resource_limits(self):
        self.legacy()
        with patch('envscope.csnap_archive.LIMIT', 8):
            with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)
        with patch('envscope.csnap_archive.FILES', 0):
            with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)
        with patch('envscope.csnap_archive.CENTRAL_LIMIT', 1):
            with self.assertRaises(AccountError): self.archive.import_archive(str(self.file),'C',PASSWORD)
        self.assertFalse((self.manager.accounts_dir/'C').exists())

    def test_failed_final_import_keeps_preexisting_recovery_data(self):
        self.legacy()
        from envscope import csnap_archive
        original = csnap_archive._unpack
        def pending(*args):
            original(*args)
            (self.manager.accounts_dir/'C.new').mkdir()
            (self.manager.accounts_dir/'C.new/sole-copy').write_bytes(b'KEEP_PENDING')
        with patch.object(csnap_archive, '_unpack', side_effect=pending):
            with self.assertRaises(RecoveryRequired): self.archive.import_archive(str(self.file),'C',PASSWORD)
        self.assertEqual((self.manager.accounts_dir/'C.new/sole-copy').read_bytes(), b'KEEP_PENDING')


if __name__ == '__main__':
    unittest.main()
