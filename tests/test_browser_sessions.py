import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import psutil

from envscope.accounts import AccountError
from envscope.browser_sessions import SessionStore, MARKER, process_alive, profile_running, start_worker, _read, _write
from envscope.isolated_browser import IsolatedBrowser
from envscope.operations import Operations
from envscope.state import StateStore

TOKEN = 'a'*32


class BrowserSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name).resolve()
        self.root = self.home/'.envscope/browser-sessions'
        self.running = Mock(return_value=False)
        self.alive = Mock(return_value=False)
        self.store = SessionStore(self.root, 'Windows', running=self.running, alive=self.alive,
                                  clock=lambda:2000, pause=lambda delay:None)

    def session(self, token=TOKEN):
        profile = self.store.create(token)
        (profile/'Cookies').write_bytes(b'FAKE_SESSION_PRIVATE_CONTENT')
        with patch('envscope.browser_sessions.process_birth',return_value=1234):
            self.store.launched(token,Mock(pid=123))
        return profile

    def restart(self):
        return SessionStore(self.root,'Windows',running=self.running,alive=self.alive,clock=lambda:3000,pause=lambda _:None)

    def test_read_only_inventory_has_no_directory_or_lock_side_effects(self):
        self.assertEqual(self.store.inspect()['sessions'],0)
        self.assertFalse(self.home.joinpath('.envscope').exists())

    def test_restart_recovers_closed_profile_and_logs_metadata_only(self):
        self.session()
        result = self.restart().cleanup()
        self.assertEqual((result['removed'],result['retained'],result['unverified']),(1,0,0))
        self.assertFalse((self.root/TOKEN).exists())
        events = b''.join(p.read_bytes() for p in (self.root.parent/'browser-cleanup-events').glob('*'))
        self.assertIn(b'removed',events)
        self.assertNotIn(b'FAKE_SESSION_PRIVATE_CONTENT',events)
        self.assertNotIn(str(self.home).encode(),events)

    def test_live_or_unreadable_process_is_retained_without_profile_deletion(self):
        profile = self.session()
        for state in (True,None):
            self.alive.return_value = state
            self.assertEqual(self.restart().cleanup()['retained'],1)
            self.assertTrue((profile/'Cookies').exists())
        self.alive.return_value = False
        self.running.return_value = None
        self.assertEqual(self.restart().cleanup(allow_legacy=True)['retained'],1)
        self.assertTrue((profile/'Cookies').exists())

    def test_second_process_snapshot_can_cancel_cleanup(self):
        profile = self.session()
        self.running.side_effect=[False,True]
        self.assertEqual(self.restart().cleanup()['retained'],1)
        self.assertTrue(profile.exists())

    def test_pid_reuse_is_not_the_original_launcher_and_access_denied_is_unknown(self):
        process = Mock();process.create_time.return_value=456
        with patch('envscope.browser_sessions.psutil.Process',return_value=process):
            self.assertIs(process_alive(123,123),False)
        with patch('envscope.browser_sessions.psutil.Process',side_effect=psutil.AccessDenied(123)):
            self.assertIsNone(process_alive(123,123))
        with patch('envscope.browser_sessions.psutil.Process',side_effect=psutil.NoSuchProcess(123)):
            self.assertIs(process_alive(123,123),False)

    def test_bad_record_and_unapproved_cleanup_never_remove_data(self):
        profile = self.session()
        marker = self.root/TOKEN/MARKER
        original = marker.read_bytes()
        invalid = []
        for key,value in [('cleanup_authorized',False),('cleanup_authorized',1),('token','b'*32),('pid',True),('birth',float('nan')),('phase','other'),('created',10**12)]:
            record = json.loads(original);record[key]=value;invalid.append(json.dumps(record).encode())
        invalid.extend([b'{bad',b'{"cleanup_authorized":false,"cleanup_authorized":true}',b'['*2000+b']'*2000])
        for data in invalid:
            with self.subTest(data=data[:70]):
                marker.write_bytes(data)
                self.assertEqual(self.restart().inspect()['unverified'],1)
                self.assertEqual(self.restart().cleanup(allow_legacy=True)['unverified'],1)
                self.assertTrue((profile/'Cookies').exists())
        marker.write_bytes(original)

    def test_shared_marker_file_and_invalid_scope_are_refused(self):
        self.session()
        marker = self.root/TOKEN/MARKER
        os.link(marker,self.home/'shared-marker')
        self.assertEqual(self.restart().cleanup()['unverified'],1)
        with self.assertRaises(AccountError): SessionStore(self.home/'some-other-directory')
        for token in ('../outside','/absolute','A'*32,False):
            with self.subTest(token=token), self.assertRaises(AccountError): self.store.read(token)

    def test_interrupted_cleanup_keeps_journal_and_retries(self):
        profile = self.session()
        (profile/'second').write_bytes(b'ANOTHER_FIXTURE')
        def fail(path):
            (path/'second').unlink()
            raise PermissionError('fixture interruption')
        with patch('envscope.browser_sessions.shutil.rmtree',side_effect=fail):
            result = self.restart().cleanup()
        self.assertEqual(result['state'],'partial')
        self.assertEqual(self.restart().inspect()['pending'],1)
        self.assertEqual(self.store.read(TOKEN)['phase'],'cleaning')
        self.assertEqual(self.restart().cleanup()['removed'],1)

    def test_extra_files_outside_profile_are_preserved(self):
        profile = self.session()
        extra = self.root/TOKEN/'my-notes';extra.write_bytes(b'KEEP_USER_FILE')
        self.assertEqual(self.restart().cleanup()['unverified'],1)
        self.assertTrue(profile.exists())
        self.assertEqual(extra.read_bytes(),b'KEEP_USER_FILE')

    def test_old_flat_profiles_require_explicit_confirmation_and_never_touch_daily_profile(self):
        self.root.mkdir(parents=True)
        old = self.root/TOKEN;old.mkdir();(old/'Cookies').write_bytes(b'OLD_FIXTURE')
        daily = self.home/'Daily Browser';daily.mkdir();(daily/'Cookies').write_bytes(b'DAILY_MUST_STAY')
        self.assertEqual(self.store.cleanup()['legacy'],1)
        self.assertTrue(old.exists())
        self.assertEqual(self.store.cleanup(allow_legacy=True)['removed'],1)
        self.assertEqual((daily/'Cookies').read_bytes(),b'DAILY_MUST_STAY')

    def test_startup_crash_record_needs_confirmed_recovery_and_no_observed_browser(self):
        profile = self.store.create(TOKEN)
        (profile/'Cookies').write_bytes(b'PARTIAL_STARTUP_FIXTURE')
        self.assertEqual(self.restart().cleanup()['retained'],1)
        self.assertEqual(self.restart().cleanup(allow_legacy=True)['removed'],1)

    def test_cleanup_and_launch_are_serialized_across_store_instances(self):
        self.session()
        with self.store.lock():
            with self.assertRaises(AccountError): self.restart().cleanup()
        self.assertTrue((self.root/TOKEN/'profile').exists())

    def test_symlink_session_never_reaches_external_directory(self):
        self.root.mkdir(parents=True)
        external = self.home/'external';external.mkdir();(external/'keep').write_bytes(b'KEEP')
        try:
            (self.root/TOKEN).symlink_to(external,target_is_directory=True)
        except OSError:
            self.skipTest('Directory symlinks require a Windows developer/admin capability')
        self.assertEqual(self.store.cleanup(allow_legacy=True)['unverified'],1)
        self.assertEqual((external/'keep').read_bytes(),b'KEEP')

    def test_process_snapshot_distinguishes_closed_and_unknown(self):
        browser = Mock();browser.info={'name':'chrome.exe'};browser.cmdline.return_value=['chrome','--user-data-dir='+str(self.root/TOKEN/'profile')]
        with patch('envscope.browser_sessions.psutil.process_iter',return_value=[browser]):
            self.assertIs(profile_running(self.root/TOKEN/'profile','Windows'),True)
        browser.cmdline.side_effect=psutil.AccessDenied(123)
        with patch('envscope.browser_sessions.psutil.process_iter',return_value=[browser]):
            self.assertIsNone(profile_running(self.root/TOKEN/'profile','Windows'))
        with patch('envscope.browser_sessions.psutil.process_iter',return_value=[]):
            self.assertIs(profile_running(self.root/TOKEN/'profile','Darwin'),False)

    def test_only_demonstrably_older_unreadable_processes_are_unrelated(self):
        browser=Mock();browser.info={'name':'chrome.exe'}
        browser.cmdline.side_effect=psutil.AccessDenied(123)
        browser.create_time.return_value=1000
        with patch('envscope.browser_sessions.psutil.process_iter',return_value=[browser]):
            self.assertIs(profile_running(self.root/TOKEN/'profile','Windows',2000),False)
        browser.create_time.return_value=2000
        with patch('envscope.browser_sessions.psutil.process_iter',return_value=[browser]):
            self.assertIsNone(profile_running(self.root/TOKEN/'profile','Windows',2000))
        browser.create_time.return_value=1000
        with patch('envscope.browser_sessions.psutil.process_iter',return_value=[browser]):
            self.assertIsNone(profile_running(self.root/TOKEN/'profile','Windows',time.time()+3600))

    def test_atomic_status_replacement_and_reading_can_run_concurrently(self):
        self.root.parent.mkdir(parents=True)
        path=self.root.parent/'concurrency.private.json'
        _write(path,{'generation':0})
        failures=[]
        def writer():
            try:
                for index in range(100): _write(path,{'generation':index})
            except Exception as error: failures.append(type(error).__name__)
        thread=threading.Thread(target=writer);thread.start()
        try:
            for _ in range(100):
                self.assertIs(type(_read(path)['generation']),int)
        finally: thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures,[])

    def test_resume_requests_cleanup_only_for_previously_authorized_records(self):
        worker=Mock()
        browser=IsolatedBrowser(self.home,launcher=Mock(),worker=worker,running=lambda _:False)
        self.assertEqual(browser.resume_cleanup()['state'],'not_needed')
        worker.assert_not_called()
        self.session()
        self.assertEqual(browser.resume_cleanup()['state'],'requested')
        worker.assert_called_once_with(self.root)

    @unittest.skipUnless(os.name=='nt','Windows sharing handles')
    def test_metadata_replace_retries_transient_denial_and_preserves_persistent_failure(self):
        self.root.parent.mkdir(parents=True)
        path=self.root.parent/'replace.private.json'
        _write(path,{'generation':0})
        replace=os.replace
        def busy_then_replace(source,destination):
            if calls.pop(0): raise PermissionError('owned transient sharing fixture')
            return replace(source,destination)
        calls=[True,True,False]
        with patch('envscope.browser_sessions.os.replace',side_effect=busy_then_replace):
            _write(path,{'generation':1})
        self.assertEqual(_read(path),{'generation':1})
        with patch('envscope.browser_sessions.os.replace',side_effect=PermissionError('owned denial fixture')):
            with self.assertRaises(PermissionError): _write(path,{'generation':2})
        self.assertEqual(_read(path),{'generation':1})
        self.assertEqual(list(path.parent.glob('*.part')),[])

    def test_worker_launch_is_hidden_detached_and_contains_no_login_url_or_proxy(self):
        with patch('envscope.browser_sessions.subprocess.Popen') as launch:
            start_worker(self.root)
        args,options=launch.call_args.args[0],launch.call_args.kwargs
        self.assertIn('--root',args)
        self.assertFalse(any('http' in arg or 'proxy' in arg for arg in args))
        self.assertNotIn('shell',options)
        if os.name=='nt': self.assertTrue(options['creationflags'])
        else: self.assertIs(options['start_new_session'],True)

    def test_cleanup_endpoint_requires_a_strict_boolean(self):
        browser = IsolatedBrowser(self.home,launcher=Mock(),running=lambda _:False)
        operations = Operations(StateStore(self.home/'settings'),self.home)
        operations.isolated_browser = browser
        self.root.mkdir(parents=True);(self.root/TOKEN).mkdir()
        for confirm in (None,False,1,'true'):
            self.assertEqual(operations.run('browser-cleanup',{},confirm)['state'],'confirmation_required')
            self.assertTrue((self.root/TOKEN).exists())
        self.assertEqual(operations.run('browser-cleanup',{},True)['removed'],1)

    def test_invalid_fixture_arguments_cannot_fall_through_to_the_normal_app(self):
        from envscope import desktop
        with patch('sys.argv',['EnvScope','--browser-session-fixture']), patch.object(desktop,'make_server') as server:
            with self.assertRaises(SystemExit) as error: desktop.main()
            self.assertEqual(error.exception.code,2)
            server.assert_not_called()

    @unittest.skipIf(os.name=='nt','FIFO is a POSIX-only file type')
    def test_fifo_record_is_refused_before_any_blocking_open(self):
        self.session()
        marker=self.root/TOKEN/MARKER;marker.unlink();os.mkfifo(marker)
        self.assertEqual(self.store.inspect()['unverified'],1)
        self.assertEqual(self.store.cleanup()['unverified'],1)


if __name__=='__main__':
    unittest.main()
