import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile
from types import SimpleNamespace

from envscope.accounts import AccountManager, AccountError
from envscope.browser import environment_finding
from envscope.cli_inventory import installation_details
from envscope.coverage import environment_portrait, feature_catalog, FEATURES
from envscope.isolated_browser import IsolatedBrowser, validate_url
from envscope.legacy import LegacyBridge
from envscope.model import utc_now
from envscope.operations import Operations
from envscope.snapshot_archive import SnapshotArchive, _encrypt, _unpack
from envscope.state import StateStore

PASSWORD = 'fixture-only-password-123'


class EncryptedArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manager = AccountManager(self.root/'state',self.root/'live')
        self.manager.accounts_dir.mkdir(parents=True)
        self.current_file = self.manager.state_dir/self.manager.current_filename
        self.current_file.write_text('A')
        self.manager.data_dir.mkdir()
        self.profile = self.manager.accounts_dir/'B'
        self.profile.mkdir()
        (self.profile/'empty').mkdir()
        (self.profile/'fixture.txt').write_text('PRIVATE_ACCOUNT_FIXTURE',encoding='utf-8')
        self.archives = SnapshotArchive(self.manager,self.root/'work')
        self.file = self.root/'backup.envsnap'

    def test_authenticated_round_trip_preserves_exact_files_and_empty_directories(self):
        result = self.archives.export('B',str(self.file),PASSWORD)
        self.assertTrue(result['verified'])
        self.assertNotIn(b'PRIVATE_ACCOUNT_FIXTURE',self.file.read_bytes())
        self.assertNotIn(b'fixture.txt',self.file.read_bytes())
        self.assertEqual(list((self.root/'work').iterdir()),[])
        self.archives.import_archive(str(self.file),'C',PASSWORD)
        self.assertEqual((self.manager.accounts_dir/'C/fixture.txt').read_bytes(),(self.profile/'fixture.txt').read_bytes())
        self.assertTrue((self.manager.accounts_dir/'C/empty').is_dir())
        self.assertEqual(list((self.root/'work').iterdir()),[])
        self.assertEqual(self.current_file.read_text(),'A')

    def test_wrong_password_truncation_and_tampering_never_write_slot(self):
        self.archives.export('B',str(self.file),PASSWORD)
        original = self.file.read_bytes()
        cases = [(original,'wrong-fixture-password'),(original[:-1],PASSWORD),
                 (original[:44]+bytes([original[44]^1])+original[45:],PASSWORD),
                 (original[:8]+bytes([original[8]^1])+original[9:],PASSWORD)]
        for content,password in cases:
            with self.subTest(length=len(content),password_wrong=password!=PASSWORD):
                self.file.write_bytes(content)
                with self.assertRaises(AccountError):
                    self.archives.import_archive(str(self.file),'C',password)
                self.assertFalse((self.manager.accounts_dir/'C').exists())
                self.assertEqual(list((self.root/'work').iterdir()),[])

    def test_active_occupied_and_existing_destinations_are_refused(self):
        with self.assertRaises(AccountError):
            self.archives.export('A',str(self.file),PASSWORD)
        self.assertFalse(self.file.exists())
        self.archives.export('B',str(self.file),PASSWORD)
        before = self.file.read_bytes()
        with self.assertRaises(ValueError):
            self.archives.export('B',str(self.file),PASSWORD)
        with self.assertRaises(AccountError):
            self.archives.import_archive(str(self.file),'B',PASSWORD)
        self.assertEqual(self.file.read_bytes(),before)

    def test_authenticated_archive_still_rejects_traversal_devices_and_duplicate_names(self):
        for name in ('data/../../outside','data/C:evil','data/a\\b','data/NUL.txt','data/a./x','data/./x','data//x'):
            with self.subTest(name=name):
                archive = self.root/'attack.zip'
                with zipfile.ZipFile(archive,'w') as z:
                    z.writestr('manifest.json','{"format":1,"files":{}}')
                    entry = zipfile.ZipInfo()
                    entry.filename = name  # Preserve adversarial backslashes on Windows too.
                    z.writestr(entry,'fixture')
                with self.assertRaises(AccountError):
                    _unpack(archive,self.root/'unpack')
                self.assertFalse((self.root/'unpack').exists())

    def test_authenticated_false_manifest_is_rejected_before_managed_import(self):
        archive = self.root/'attack.zip'
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('manifest.json','{"format":1,"files":{".":["directory"]}}')
            z.writestr('data/extra.txt','fixture')
        _encrypt(archive,self.file,PASSWORD)
        with self.assertRaises(AccountError):
            self.archives.import_archive(str(self.file),'C',PASSWORD)
        self.assertFalse((self.manager.accounts_dir/'C').exists())


class IsolatedBrowserTests(unittest.TestCase):
    def test_both_platforms_use_private_profiles_no_spoofing_and_cleanup_only_after_exit(self):
        for system in ('Windows','Darwin'):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as directory, patch('envscope.isolated_browser.threading.Thread'):
                root = Path(directory).resolve()
                executable = root/'fixture-browser'
                executable.write_text('NOT_EXECUTABLE')
                process = Mock();process.poll.return_value=None
                launch = Mock(return_value=process)
                running = Mock(return_value=True)
                browser = IsolatedBrowser(root,system,lambda:[('Fixture',executable)],launch,running)
                settings = {'usage':'web','connection_mode':'direct'}
                self.assertEqual(browser.open('https://claude.ai/',settings,lambda:False)['state'],'blocked')
                launch.assert_not_called()
                self.assertFalse(browser.root.exists())
                result = browser.open('https://claude.ai/',settings,lambda:True)
                argv = launch.call_args.args[0]
                self.assertIn('--disable-extensions',argv)
                self.assertIn('--no-proxy-server',argv)
                self.assertTrue(any(v.startswith('--user-data-dir=') for v in argv))
                self.assertFalse(any(v.startswith(('--lang','--user-agent','--timezone')) for v in argv))
                self.assertNotIn('https://claude.ai/',str(result))  # Login URLs never echoed into reports.
                self.assertEqual(browser.cleanup()['retained'],1)
                process.poll.return_value=0
                running.return_value=None
                self.assertEqual(browser.cleanup()['retained'],1)
                running.return_value=False
                self.assertEqual(browser.cleanup()['removed'],1)
                self.assertEqual(list(browser.root.iterdir()),[])

    def test_shell_schemes_credentials_and_cli_only_targets_refused(self):
        for value in ('file:///etc/passwd','javascript:alert(1)','https://a:b@example.com','https://example.com/\n--x','--flag'):
            with self.assertRaises(ValueError):
                validate_url(value)
        with tempfile.TemporaryDirectory() as directory:
            browser = IsolatedBrowser(directory,finder=lambda:[])
            gate = Mock()
            self.assertEqual(browser.open('https://claude.ai/',{'usage':'cli'},gate)['state'],'blocked')
            gate.assert_not_called()

    def test_proxy_argument_is_explicit_and_does_not_become_shell_code(self):
        with tempfile.TemporaryDirectory() as directory, patch('envscope.isolated_browser.threading.Thread'):
            root = Path(directory).resolve()
            exe = root/'browser';exe.touch()
            launch = Mock()
            browser = IsolatedBrowser(root,finder=lambda:[('Fixture',exe)],launcher=launch)
            browser.open('https://example.com/?a=$(bad)',{'usage':'web','connection_mode':'http_proxy','target_proxy':'http://127.0.0.1:8000'},lambda:True)
            args = launch.call_args.args[0]
            self.assertIn('--proxy-server=http://127.0.0.1:8000',args)
            self.assertEqual(args[-1],'https://example.com/?a=$(bad)')
            self.assertNotIn('shell',launch.call_args.kwargs)


class EnvironmentCoverageTests(unittest.TestCase):
    def test_native_archive_dialog_preserves_complete_paths_and_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            operations = Operations(StateStore(memory=True), directory, legacy=Mock(), discoverer=lambda:[])
            operations.desktop_runtime = Mock()
            filename = '/fixture/账户 备份.envsnap'
            fake_webview = SimpleNamespace(SAVE_DIALOG=1, OPEN_DIALOG=2)
            with patch.dict(sys.modules, {'webview':fake_webview}):
                for mode in ('export','import'):
                    for value, expected in ((filename,filename), ((filename,),filename), (None,None), ((),None)):
                        with self.subTest(mode=mode,value=value):
                            operations.desktop_runtime.window.create_file_dialog.return_value = value
                            result = operations.run('archive-choose-file', {'mode':mode})
                            self.assertEqual(result['file'],expected)
                            self.assertEqual(result['state'],'selected' if expected else 'cancelled')

    def test_changed_guard_mode_and_unreadable_mode_cannot_pass(self):
        from envscope.baseline import guard_finding, installed_guard_mode
        running = {'registered':True,'enabled':True,'running':True}
        self.assertEqual(guard_finding(running,{'client':'sing-box'}).status,'unknown')
        self.assertEqual(guard_finding({**running,'configured_mode':'clash-verge'},{'client':'sing-box'}).status,'fail')
        self.assertEqual(guard_finding({**running,'configured_mode':'sing-box'},{'client':'sing-box'}).status,'unknown')
        self.assertEqual(guard_finding({**running,'identity_verified':True,'configured_mode':'sing-box'},{'client':'sing-box'}).status,'pass')
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory).resolve()/'guard';source.write_text('MODE="sing-box"\n')
            self.assertEqual(installed_guard_mode('Darwin',source)['configured_mode'],'sing-box')
            source.write_text('MODE="__PROXY_MODE__"\n')
            self.assertIsNone(installed_guard_mode('Darwin',source)['configured_mode'])

    def test_web_browser_gate_is_separate_from_desktop_and_rejects_stale_or_unsupported_region(self):
        from envscope.readiness import browser_readiness, launch_readiness
        from scripts.environment_fixtures import report, target
        with tempfile.TemporaryDirectory() as directory:
            preferences=target('Windows',usage='web')
            value=report(directory,preferences)
            self.assertTrue(browser_readiness(value,preferences))
            self.assertFalse(launch_readiness(value,preferences)['ready'])
            value['created_at']='2020-01-01T00:00:00+00:00'
            self.assertFalse(browser_readiness(value,preferences))
            preferences['usage_country']='CN'
            self.assertFalse(browser_readiness(report(directory,preferences),preferences))

    def test_browser_metadata_is_whitelisted_scoped_and_stale_is_not_a_pass(self):
        raw = {'created_at':utc_now(),'environment':{'timezone':'Asia/Shanghai','languages':['zh-CN'],
                'serial':'PRIVATE','hardware_threads':True,'automated':True,'renderer':'Software fixture'}}
        value = environment_finding(raw)
        self.assertEqual(value.status,'pass')
        self.assertNotIn('PRIVATE',str(value))
        self.assertNotIn('hardware_threads',value.evidence[0])
        raw['created_at']='2020-01-01T00:00:00+00:00'
        self.assertEqual(environment_finding(raw).status,'unknown')
        self.assertEqual(environment_finding(None).status,'unknown')

    def test_portrait_has_eight_dimensions_and_never_turns_missing_evidence_into_pass(self):
        value = environment_portrait({'findings':[]})
        self.assertEqual(len(value['dimensions']),8)
        self.assertTrue(all(d['pending']>0 for d in value['dimensions']))
        self.assertTrue(all(d['measured']==0 for d in value['dimensions']))
        value = environment_portrait({'findings':[{'id':'target.region','title':'region','status':'fail','summary':'unsupported'}]})
        self.assertEqual(value['dimensions'][0]['problems'],1)

    def test_catalog_preserves_upstream_scope_and_explicit_install_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            for system in ('Windows','Darwin'):
                legacy = LegacyBridge(system,directory).capabilities()
                rows = feature_catalog(legacy,{'available':False})['rows']
                self.assertEqual(len(rows),len(FEATURES))
                indexed = {r['id']:r['state'] for r in rows}
                self.assertEqual(indexed['guard'],'native')
                self.assertEqual(indexed['browser'],'needs_browser')
                self.assertEqual(indexed['watchdog'],'native')

    def test_passive_cli_inventory_finds_conflicts_without_executing_entrypoints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('one','two'):
                (root/name).mkdir()
                (root/name/'claude').write_text('raise AssertionError("MUST NOT RUN")')
            (root/'one/package.json').write_text(json.dumps({'name':'@anthropic-ai/claude-code','version':'fixture-1'}))
            value = installation_details(root,path=os.pathsep.join(str(root/n) for n in ('one','two')))
            self.assertEqual(len(value['installations']),2)
            self.assertEqual(value['installations'][0]['version'],'fixture-1')

    def test_known_region_restriction_blocks_legacy_writes_and_requires_archive_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(memory=True);store.save_settings({'usage_country':'CN'})
            legacy = Mock()
            operations = Operations(store,directory,legacy=legacy,discoverer=lambda:[])
            for action in ('fix','install','set-region'):
                self.assertEqual(operations.run(action,{},confirmed=True)['state'],'blocked')
            legacy.run.assert_not_called()
            with patch.object(operations.archives,'export') as export:
                result = operations.run('archive-export',{'slot':'B','file':'fixture','password':PASSWORD})
                self.assertEqual(result['state'],'confirmation_required')
                export.assert_not_called()
