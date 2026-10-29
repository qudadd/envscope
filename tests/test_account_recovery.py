"""Crash-boundary and identity checks on disposable profiles only."""
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from envscope.accounts import AccountError, AccountManager, RecoveryRequired, _copy_verified, _manifest
from envscope.operations import Operations, quit_account_claude
from envscope.profile_copy import copy_profile_file, _clone
from envscope.state import StateStore


class Interrupted(BaseException):
    pass


class AccountRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.state, self.data = self.root/'state', self.root/'Claude'
        self.stopped, self.launched = [], []
        self.manager = AccountManager(self.state, self.data, 'current.txt',
                                      lambda: self.stopped.append(True) or True,
                                      lambda: self.launched.append(True) or True)
        for path, identity in [(self.data, 'A-new'), (self.state/'accounts/A', 'A-old'),
                               (self.state/'accounts/B', 'B')]:
            path.mkdir(parents=True)
            for name in ('Local State', 'Cookies', 'Local Storage/leveldb/oauth', 'IndexedDB/local'):
                item = path/name
                item.parent.mkdir(exist_ok=True, parents=True)
                item.write_text(identity + ':' + name, encoding='utf-8')
        (self.state/'current.txt').write_text('A')
        self.original = _manifest(self.data)
        self.original_archive = _manifest(self.state/'accounts/A')
        self.target = _manifest(self.state/'accounts/B')

    def tearDown(self):
        self.tmp.cleanup()

    def interrupt(self, boundary):
        replace = os.replace
        def interrupted(source, destination):
            result = replace(source, destination)
            src, dst = Path(source), Path(destination)
            match = ((boundary == 'journal-start' and dst == self.manager.journal_file)
                     or (boundary == 'old-archive' and dst.name == 'A.previous')
                     or (boundary == 'new-archive' and src.name == 'A.new')
                     or (boundary == 'old-live' and dst.name == 'Claude.previous')
                     or (boundary == 'new-live' and src.name == 'Claude.new')
                     or (boundary == 'marker' and dst.name == 'current.txt')
                     or (boundary == 'committed' and dst == self.manager.journal_file
                         and json.loads(dst.read_text())['state'] == 'committed'))
            if match:
                raise Interrupted()
            return result
        with patch('envscope.accounts.os.replace', side_effect=interrupted), self.assertRaises(Interrupted):
            self.manager.switch('B', lambda: True)
        self.assertFalse(self.launched)

    def restore(self):
        plan = self.manager.recovery.plan()
        self.assertEqual(plan['state'], 'planned', plan)
        result = self.manager.recovery.apply(plan['plan_id'], True)
        self.assertEqual(result['state'], 'completed')
        self.assertFalse(result['launched'])
        self.assertEqual(self.manager._pending(), [])
        return result

    def test_all_rename_boundaries_restore_previous_whole_identity(self):
        for boundary in ('journal-start', 'old-archive', 'new-archive', 'old-live', 'new-live', 'marker'):
            with self.subTest(boundary=boundary):
                self.interrupt(boundary)
                # A new application session can reconstruct recovery; no RAM state is needed.
                self.manager = AccountManager(self.state, self.data, 'current.txt', lambda: True)
                result = self.restore()
                self.assertEqual(result['mode'], 'rollback')
                self.assertEqual(_manifest(self.data), self.original)
                self.assertEqual(_manifest(self.state/'accounts/A'), self.original_archive)
                self.assertEqual(_manifest(self.state/'accounts/B'), self.target)
                self.assertEqual(self.manager._read_current(), 'A')

    def test_completed_exchange_preserved_when_cleanup_interrupted(self):
        self.interrupt('committed')
        result = self.restore()
        self.assertEqual(result['mode'], 'finish')
        self.assertEqual(_manifest(self.data), self.target)
        self.assertEqual(_manifest(self.state/'accounts/A'), self.original)
        self.assertEqual(self.manager._read_current(), 'B')
        self.assertGreater(result['preserved_copies'], 0)

    def test_recovery_interruption_can_be_retried_without_overwrite(self):
        self.interrupt('new-live')
        plan = self.manager.recovery.plan()
        replace = os.replace
        def interrupted(source, destination):
            result = replace(source, destination)
            if Path(destination) == self.data:
                raise Interrupted()
            return result
        with patch('envscope.account_recovery.os.replace', side_effect=interrupted), self.assertRaises(Interrupted):
            self.manager.recovery.apply(plan['plan_id'], True)
        result = self.restore()
        self.assertEqual(result['mode'], 'rollback')
        self.assertEqual(_manifest(self.data), self.original)
        self.assertEqual(_manifest(self.state/'accounts/A'), self.original_archive)

    def test_confirmation_preview_and_changed_files_do_not_write(self):
        self.interrupt('old-live')
        plan = self.manager.recovery.plan()
        before = _manifest(self.root)
        for confirmation in (False, None, 1, 'yes'):
            result = self.manager.recovery.apply(plan['plan_id'], confirmation)
            self.assertEqual(result['state'], 'confirmation_required')
            self.assertEqual(_manifest(self.root), before)
        (self.data.with_name('Claude.new')/'new-file').write_text('another writer')
        with self.assertRaisesRegex(RecoveryRequired, '变化'):
            self.manager.recovery.apply(plan['plan_id'], True)
        self.assertFalse(self.data.exists())

    def test_changed_committed_profile_and_unknown_legacy_journal_require_manual_recovery(self):
        self.interrupt('committed')
        (self.data/'Cookies').write_text('fresh session from an external launch')
        self.assertEqual(self.manager.recovery.plan()['state'], 'blocked')
        self.manager.journal_file.write_text('{"schema_version":1,"slot":"B"}')
        self.assertFalse(self.manager.recovery.status()['available'])
        self.assertEqual(self.manager.recovery.plan()['state'], 'blocked')

    def test_missing_original_or_malicious_journal_never_guesses(self):
        self.interrupt('journal-start')
        (self.data/'Cookies').write_text('changed original')
        self.assertEqual(self.manager.recovery.plan()['state'], 'blocked')
        value = json.loads(self.manager.journal_file.read_text())
        value['archived'] = '../outside'
        self.manager.journal_file.write_text(json.dumps(value))
        self.assertFalse(self.manager.recovery.status()['available'])
        self.assertEqual(self.manager.recovery.plan()['state'], 'blocked')

    def test_failed_exit_and_expired_plan_keep_all_copies(self):
        self.interrupt('old-live')
        plan = self.manager.recovery.plan()
        self.manager.stop_app = lambda: False
        before = _manifest(self.root)
        with self.assertRaises(AccountError):
            self.manager.recovery.apply(plan['plan_id'], True)
        self.assertEqual(_manifest(self.root), before)
        plan = self.manager.recovery.plan()
        with patch('envscope.account_recovery.time.monotonic', return_value=10**12), self.assertRaises(RecoveryRequired):
            self.manager.recovery.apply(plan['plan_id'], True)

    def test_imported_or_untracked_identity_recovery_does_not_invent_a_marker(self):
        (self.state/'current.txt').unlink()
        shutil.rmtree(self.state/'accounts/A')
        self.interrupt('new-live')
        self.restore()
        self.assertIsNone(self.manager._read_current())
        self.assertEqual(_manifest(self.data), self.original)
        self.assertFalse((self.state/'accounts/A').exists())

    def test_real_child_exit_retains_journal_and_readable_profiles(self):
        code = '''import os, sys
from pathlib import Path
from envscope.accounts import AccountManager
root=Path(sys.argv[1]); replace=os.replace
def fail(src,dst):
    result=replace(src,dst)
    if Path(src).name=='Claude.new': os._exit(71)
    return result
os.replace=fail
AccountManager(root/'state',root/'Claude','current.txt',lambda:True).switch('B',lambda:True)
'''
        result = subprocess.run([sys.executable, '-c', code, str(self.root)], capture_output=True, timeout=30,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 71, result.stderr)
        self.restore()
        self.assertEqual(_manifest(self.data), self.original)

    def test_recovery_api_no_report_required_no_credentials_in_journal_or_events(self):
        self.interrupt('new-live')
        operations = Operations(StateStore(memory=True), self.root, account_manager=self.manager, discoverer=lambda: [])
        plan = operations.run('account-recovery-plan', {})
        result = operations.run('account-recovery-apply', {'plan_id': plan['plan_id']}, True)
        self.assertEqual(result['state'], 'completed')
        with self.assertRaises(ValueError):
            operations.run('account-recovery-apply', {'plan_id': 'x', 'path': '../bad'}, True)
        logs = ''.join(p.read_text() for p in (self.state/'account-events').glob('*.jsonl'))
        self.assertNotIn('A-new', logs)
        self.assertNotIn('Local Storage', logs)

    def test_forced_exit_is_explicit_per_switch_and_still_requires_verified_exit(self):
        forced = []
        self.manager.stop_app = lambda: False
        self.manager.force_stop_app = lambda: forced.append(True) or True
        with self.assertRaises(AccountError):
            self.manager.switch('B', lambda: True)
        self.assertFalse(forced)
        self.assertEqual(_manifest(self.data), self.original)
        for value in (1, 'true', None):
            with self.assertRaises(AccountError):
                self.manager.switch('B', lambda: True, allow_force=value)
        self.manager.force_stop_app = lambda: forced.append(True) or False
        with self.assertRaises(AccountError):
            self.manager.switch('B', lambda: True, allow_force=True)
        self.assertEqual(_manifest(self.data), self.original)
        self.manager.force_stop_app = lambda: forced.append(True) or True
        self.manager.switch('B', lambda: True, allow_force=True)
        self.assertEqual(_manifest(self.data), self.target)
        self.assertEqual(len(forced), 2)


class ProfileCopyTests(unittest.TestCase):
    def test_native_clone_or_fallback_keeps_files_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source, target = root/'source', root/'target'
            source.mkdir(); (source/'identity').write_bytes(b'private-fixture-identity')
            _copy_verified(source, target)
            self.assertEqual((source/'identity').stat().st_nlink, 1)
            self.assertEqual((target/'identity').stat().st_nlink, 1)
            (target/'identity').write_bytes(b'new-session')
            self.assertEqual((source/'identity').read_bytes(), b'private-fixture-identity')

    def test_clone_fallback_is_narrow_and_never_cleans_unexpected_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp)/'source', Path(tmp)/'target'
            source.write_text('original')
            with patch('envscope.profile_copy.sys.platform', 'darwin'), patch('envscope.profile_copy._clone', side_effect=OSError(errno.EXDEV, 'fixture')):
                copy_profile_file(source, target)
            self.assertEqual(target.read_text(), 'original')
            target.unlink()
            with patch('envscope.profile_copy.sys.platform', 'darwin'), patch('envscope.profile_copy._clone', side_effect=OSError(errno.EACCES, 'fixture')), self.assertRaises(OSError):
                copy_profile_file(source, target)
            target.write_text('preserve partial')
            with patch('envscope.profile_copy.sys.platform', 'darwin'), patch('envscope.profile_copy._clone', side_effect=OSError(errno.EXDEV, 'fixture')), self.assertRaises(OSError):
                copy_profile_file(source, target)
            self.assertEqual(target.read_text(), 'preserve partial')

    def test_shared_writable_hardlink_cannot_join_account_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root/'source'; source.mkdir()
            original = root/'other-account'; original.write_text('identity')
            os.link(original, source/'identity')
            with self.assertRaises(AccountError):
                _copy_verified(source, root/'target')
            self.assertFalse((root/'target').exists())

    @unittest.skipUnless(sys.platform == 'darwin', 'APFS clone requires macOS')
    def test_real_macos_clone_retains_identity_and_breaks_on_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp)/'source', Path(tmp)/'target'
            source.write_bytes(b'private-identity')
            _clone(source, target)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertNotEqual(target.stat().st_ino, source.stat().st_ino)
            target.write_bytes(b'changed-target')
            self.assertEqual(source.read_bytes(), b'private-identity')

    def test_account_exit_waits_for_helpers_and_never_force_kills(self):
        from types import SimpleNamespace
        targets = [{'pid': 123, 'created': 123.45, 'exe': 'fixture'}]
        snapshot = lambda items: {'targets': items, 'unreadable': False}
        with patch('envscope.process_guard.NativeGuardIO') as cls, patch('envscope.operations.platform.system', return_value='Windows'), patch('envscope.operations._process', return_value=SimpleNamespace(returncode=0)) as run, patch('envscope.operations.time.sleep'):
            cls.return_value.snapshot.side_effect = [snapshot(targets), snapshot(targets), snapshot([])]
            self.assertTrue(quit_account_claude())
            command = run.call_args.args[0][-1]
            self.assertIn('CloseMainWindow', command)
            self.assertIn('StartTime', command)
            self.assertNotIn('Stop-Process', command)
            cls.return_value.snapshot.side_effect = [snapshot(targets)] * 31
            self.assertFalse(quit_account_claude())


if __name__ == '__main__':
    unittest.main()
