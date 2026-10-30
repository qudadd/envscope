"""Native lifecycle/update failure tests, isolated from real apps and networking."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

from envscope.desktop_runtime import DesktopRuntime, SingleInstance
from envscope import __version__
from envscope.updates import AppUpdates, API, RELEASE, allowed_url, asset_name, safe_extract, version
from envscope.state import StateStore
from envscope.app_identity import build_identity


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name))
        major, minor, _ = version(RELEASE)[:3]
        self.future_base = f'v{major}.{minor+1}.0'
        self.tag = self.future_base + '-alpha.1'
        self.refresh_package()
        self.release = self.metadata()
        self.calls = []
        self.updates = AppUpdates(self.store, self.fetch, 'Windows', 'AMD64')

    def refresh_package(self,change=None):
        identity={**build_identity('Windows'),'release':self.tag,'version':self.tag[1:].split('-')[0],'build_version':self.tag[1:].split('-')[0],**(change or {})}
        self.data = self.archive({'EnvScope/EnvScope.exe': b'MZ-TEST-NOT-EXECUTABLE', 'EnvScope/data.txt': b'test',
                                 'EnvScope/build-identity.json':json.dumps(identity).encode()})
        self.size = len(self.data)
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.checksum = self.digest

    def archive(self, values):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            for name, value in values.items():
                z.writestr(name, value)
        return out.getvalue()

    def metadata(self):
        prefix = 'https://github.com/qudadd/envscope/releases/download/' + self.tag + '/'
        return {'draft': False, 'prerelease': True, 'tag_name': self.tag, 'body': 'Fixture notes', 'assets': [
            {'name': 'EnvScope-Windows-x64.zip', 'state': 'uploaded', 'size': self.size, 'digest': 'sha256:' + self.digest, 'browser_download_url': prefix + 'EnvScope-Windows-x64.zip'},
            {'name': 'SHA256SUMS.txt', 'state': 'uploaded', 'browser_download_url': prefix + 'SHA256SUMS.txt'}]}

    def fetch(self, url, limit, destination=None):
        self.calls.append(url)
        if url.startswith(API):
            return json.dumps([self.release]).encode()
        if '/commits/' in url:
            return b'{"sha":"0123456789012345678901234567890123456789"}'
        if url.endswith('SHA256SUMS.txt'):
            return (self.checksum + '  EnvScope-Windows-x64.zip\n').encode()
        if destination:
            destination.write_bytes(self.data)
            return len(self.data)
        raise AssertionError('Unexpected fixture request')

    def test_check_never_installs_and_confirmation_is_required(self):
        self.assertEqual(self.updates.check()['state'], 'available')
        self.assertFalse((self.store.root / 'updates').exists())
        self.assertEqual(self.updates.install(self.tag)['state'], 'confirmation_required')
        self.assertFalse(any(u.endswith('.zip') for u in self.calls))

    def test_verified_side_by_side_install_and_second_version_rollback(self):
        self.updates.check()
        self.assertEqual(self.updates.install(self.tag, True)['state'], 'ready')
        first = self.updates.installed()
        self.assertEqual(first.read_bytes(), b'MZ-TEST-NOT-EXECUTABLE')
        self.tag = self.future_base + '-alpha.2'
        self.refresh_package()
        self.release = self.metadata()
        self.updates.check()
        self.updates.install(self.tag, True)
        self.assertNotEqual(first, self.updates.installed())
        self.assertEqual(self.updates.rollback()['state'], 'confirmation_required')
        self.updates.rollback(True)
        self.assertEqual(first, self.updates.installed())

    def test_bad_checksum_does_not_change_installed_pointer(self):
        self.updates.check()
        self.checksum = 'f' * 64
        with self.assertRaises(ValueError):
            self.updates.install(self.tag, True)
        self.assertIsNone(self.updates.installed())
        self.assertFalse(list((self.store.root / 'updates/versions').iterdir()))

    def test_archive_hash_cannot_substitute_for_package_identity(self):
        self.refresh_package({'app_id':'another.application'})
        self.release=self.metadata();self.updates.check()
        with self.assertRaises(ValueError):self.updates.install(self.tag,True)
        self.assertIsNone(self.updates.installed())
        self.assertFalse(list((self.store.root/'updates/versions').iterdir()))

    def test_corrupt_archive_and_traversal_are_rejected(self):
        self.updates.check()
        self.data += b'corruption'
        with self.assertRaises(ValueError):
            self.updates.install(self.tag, True)
        file = self.store.root / 'bad.zip'
        file.write_bytes(self.archive({'EnvScope/../escape': b'data'}))
        with self.assertRaises(ValueError):
            safe_extract(file, self.store.root / 'stage', 'Windows')
        self.assertFalse((self.store.root / 'escape').exists())

    def test_macos_ditto_utf8_names_without_flag_are_restored(self):
        raw = bytearray(self.archive({'EnvScope.app/Contents/MacOS/EnvScope': b'\xcf\xfa\xed\xfeTEST', 'EnvScope.app/资料.txt': b'fixture'}))
        for marker, offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
            start = 0
            while (index := raw.find(marker, start)) >= 0:
                flags = struct.unpack_from('<H', raw, index + offset)[0]
                struct.pack_into('<H', raw, index + offset, flags & ~0x800)
                start = index + 4
        archive = self.store.root / 'mac.zip'
        archive.write_bytes(raw)
        safe_extract(archive, self.store.root / 'extracted', 'Darwin')
        self.assertEqual((self.store.root / 'extracted/EnvScope.app/资料.txt').read_bytes(), b'fixture')

    def test_unofficial_asset_and_missing_digest_cannot_install(self):
        self.release['assets'][0]['browser_download_url'] = 'https://evil.invalid/binary.zip'
        self.assertEqual(self.updates.check()['state'], 'up_to_date')
        self.release = self.metadata()
        del self.release['assets'][0]['digest']
        self.assertEqual(self.updates.check()['state'], 'up_to_date')

    def test_stable_channel_excludes_prerelease_and_empty_is_not_network_failure(self):
        self.assertEqual(self.updates.check(False)['state'], 'up_to_date')
        self.updates.downloader = Mock(side_effect=OSError())
        self.assertEqual(self.updates.check()['state'], 'unavailable')

    def test_expired_candidate_and_modified_executable_rejected(self):
        self.updates.check()
        self.updates.state['checked_at'] = 0
        with self.assertRaises(ValueError):
            self.updates.install(self.tag, True)
        self.updates.check()
        self.updates.install(self.tag, True)
        self.updates.installed().write_bytes(b'MODIFIED')
        with self.assertRaises(ValueError):
            self.updates.installed()

    def test_platform_and_version_validation(self):
        self.assertEqual(asset_name('Darwin', 'arm64'), 'EnvScope-macOS-arm64.zip')
        with self.assertRaises(ValueError):
            asset_name('Windows', 'arm64')
        self.assertGreater(version('v'+__version__), version(RELEASE))
        self.assertFalse(allowed_url('http://github.com/file'))
        self.assertFalse(allowed_url('https://github.com.evil.invalid/file'))
        self.assertFalse(allowed_url('https://name@github.com/file'))

    def test_installed_release_is_not_offered_as_an_update(self):
        self.tag = RELEASE
        self.release = self.metadata()
        value = self.updates.check()
        self.assertEqual(value['current'], RELEASE)
        self.assertEqual(value['state'], 'up_to_date')
        self.assertEqual(version(RELEASE)[:3], tuple(map(int, __version__.split('.'))))
        self.assertFalse(any(u.endswith('.zip') for u in self.calls))

    def test_damaged_receipt_is_not_an_executable(self):
        self.store._write('desktop-install.private.json', [])
        self.assertIsNone(self.updates.installed())
        self.store._write('desktop-install.private.json', {'active': {'version': self.tag, 'executable': 123}})
        with self.assertRaises(ValueError):
            self.updates.installed()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name))
        self.window = Mock()
        self.server = SimpleNamespace(store=self.store, audit_lock=threading.Lock())
        self.runtime = DesktopRuntime(self.server, self.window)

    def test_guard_failure_survives_restart_without_repeating_os_notification(self):
        self.server.operations=SimpleNamespace(maintenance=Mock(),timezone_service=Mock())
        self.server.operations.maintenance.status.return_value={'enabled':True,'watchdog':{'proxy':{'state':'attention'}}}
        self.server.operations.timezone_service.status.return_value={'state':'not_installed'}
        self.runtime.icon=Mock();self.runtime.ready.set();self.runtime.poll_guard()
        self.runtime.icon.notify.assert_called_once()
        again=DesktopRuntime(self.server,self.window);again.icon=Mock();again.ready.set();again.poll_guard()
        again.icon.notify.assert_not_called()
        self.assertEqual(again.guard_attention['components'],['proxy'])
        self.assertIn('envscope-guard-attention',self.window.run_js.call_args.args[0])

    def test_close_hides_only_with_a_working_tray(self):
        self.assertTrue(self.runtime.closing())
        self.runtime.icon = Mock()
        self.runtime.ready.set()
        self.assertFalse(self.runtime.closing())
        self.window.hide.assert_called_once()
        self.runtime.save({'keep_running': False})
        self.assertTrue(self.runtime.closing())

    def test_quit_during_repair_is_blocked_and_visible(self):
        self.server.audit_lock.acquire()
        self.assertFalse(self.runtime.quit())
        self.window.destroy.assert_not_called()
        self.server.audit_lock.release()
        self.assertTrue(self.runtime.quit())
        self.assertTrue(self.runtime.closing())

    def test_preferences_persist_without_changing_maintenance(self):
        self.runtime.save({'keep_running': False, 'check_updates': False})
        again = DesktopRuntime(self.server, self.window)
        self.assertFalse(again.preferences['check_updates'])
        self.assertFalse((self.store.root / 'maintenance.private.json').exists())
        with self.assertRaises(ValueError):
            self.runtime.save({'check_updates': 'false'})

    def test_corrupt_desktop_preferences_use_safe_defaults(self):
        self.store._write('desktop-preferences.private.json', [])
        self.store._write('desktop-install.private.json', 'damaged')
        runtime = DesktopRuntime(self.server, self.window)
        self.assertTrue(runtime.preferences['keep_running'])
        self.assertFalse(runtime.status()['can_rollback'])

    def test_second_instance_cannot_acquire_lock_and_can_after_exit(self):
        first, second = SingleInstance(self.store.root), SingleInstance(self.store.root)
        try:
            self.assertTrue(first.acquire())
            self.assertFalse(second.acquire())
            first.close()
            self.assertTrue(second.acquire())
        finally:
            first.close()
            second.close()
