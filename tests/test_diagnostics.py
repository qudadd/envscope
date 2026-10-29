"""Privacy, rotation and atomic save tests use only disposable user data."""
import base64
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from envscope.diagnostics import DiagnosticLog, FILES, write_archive
from envscope.operations import Operations
from envscope.state import StateStore


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve(); self.store = StateStore(self.home/'state')
        self.log = DiagnosticLog(self.store)

    def unpack(self, archive):
        with ZipFile(BytesIO(base64.b64decode(archive['data']))) as file:
            self.assertEqual(set(file.namelist()), {'summary.json','commands.jsonl','README.txt'})
            return {name:file.read(name) for name in file.namelist()}

    def test_read_and_export_do_not_create_a_log_or_invent_a_report(self):
        self.assertEqual(self.log.entries(), [])
        self.assertEqual(self.log.status()['entries'], 0)
        files = self.unpack(self.log.archive())
        self.assertEqual(json.loads(files['summary.json'])['checks'], [])
        self.assertFalse(self.log.root.exists())

    def test_optout_survives_restart_and_excludes_preexisting_logs_from_zip(self):
        self.log.record('audit', 'completed', .03)
        before = (self.log.root/FILES[1]).read_bytes()
        self.store.save_settings({'check_config':{'logging':False}})
        log = DiagnosticLog(StateStore(self.store.root))
        self.assertFalse(log.record('account-switch','completed'))
        self.assertEqual((self.log.root/FILES[1]).read_bytes(), before)
        self.assertEqual(log.entries(), [])
        self.assertEqual(self.unpack(log.archive())['commands.jsonl'], b'')

    def test_untrusted_command_status_and_poisoned_log_fields_never_export(self):
        self.log.record('PRIVATE_TOKEN_secret', 'PRIVATE_ERROR_8.8.8.8', .03)
        entry = json.loads((self.log.root/FILES[1]).read_bytes())
        entry.update(secret='PRIVATE_LOG_SECRET', username='PRIVATE_USER', ip='8.8.8.8', path=r'C:\Users\PRIVATE\oauth')
        with (self.log.root/FILES[1]).open('ab') as stream:
            stream.write(json.dumps(entry).encode()+b'\n')
            stream.write(b'garbage PRIVATE_LINE\n')
            stream.write(json.dumps({**entry,'command':'PRIVATE_COMMAND'}).encode()+b'\n')
        report = {'findings':[{'id':'http.egress','status':'fail','title':'PRIVATE_TITLE',
                               'summary':'PRIVATE_PASSWORD','evidence':[{'ip':'8.8.8.8','oauth':'PRIVATE_OAUTH'}]},
                              {'id':'unknown.PRIVATE','status':'pass'}],
                  'environment':{'target_proxy':'http://PRIVATE:KEY@localhost:9999'},'report_id':'PRIVATE_UUID'}
        files = self.unpack(self.log.archive(report))
        content = b''.join(files.values())
        self.assertNotIn(b'PRIVATE', content); self.assertNotIn(b'8.8.8.8', content)
        self.assertNotIn(b'localhost', content)
        summary = json.loads(files['summary.json'])
        self.assertEqual(summary['counts']['fail'], 1)
        self.assertEqual(summary['checks'], [{'id':'http.egress','title':'HTTP IPv4 出口交叉验证','status':'fail'}])
        self.assertEqual(len(self.log.entries()), 2)
        self.assertEqual(set(self.log.entries()[0]), {'at','command','state','duration_ms'})

    def test_rotation_bounds_both_files_and_retains_latest_entries(self):
        with patch('envscope.diagnostics.LIMIT', 2048):
            for n in range(100): self.log.record('audit','completed',n)
            self.assertTrue(all(0 < (self.log.root/name).stat().st_size <= 2048 for name in FILES))
            rows = self.log.entries()
            self.assertGreater(len(rows), 10); self.assertLess(len(rows), 100)
            self.assertEqual(rows[-1]['duration_ms'], 99000)

    def test_concurrent_instances_keep_complete_individual_records(self):
        logs = [DiagnosticLog(self.store), DiagnosticLog(self.store)]
        def write(n): return logs[n%2].record('audit','completed',n/1000)
        with ThreadPoolExecutor(max_workers=8) as pool: self.assertTrue(all(pool.map(write, range(80))))
        self.assertEqual(len(self.log.entries()),80)
        self.assertEqual({r['duration_ms'] for r in self.log.entries()}, set(range(80)))

    def test_oversized_or_hardlinked_log_is_rejected_without_copying_or_deleting_it(self):
        self.log.record('audit','completed')
        path = self.log.root/FILES[1]; before = path.read_bytes()
        other = self.home/'keep'; other.hardlink_to(path)
        self.assertFalse(self.log.safe_record('audit','failed'))
        self.assertEqual(self.log.status()['state'],'unavailable')
        self.assertEqual(self.unpack(self.log.archive())['commands.jsonl'],b'')
        with self.assertRaises(ValueError): self.log.clear(True)
        self.assertEqual(other.read_bytes(),before)
        other.unlink()
        with patch('envscope.diagnostics.LIMIT',1):
            self.assertFalse(self.log.safe_record('audit','completed'))
            self.assertEqual(path.read_bytes(),before)

    def test_log_failure_does_not_turn_an_operation_into_failure_or_repeat_it(self):
        ops = Operations(self.store, self.home, discoverer=lambda:[])
        with patch.object(ops.diagnostics,'record',side_effect=OSError('PRIVATE_FAILURE')) as record:
            result = ops.run('check-config-save',{'logging':False})
        self.assertEqual(result['state'],'completed'); record.assert_called_once()
        self.assertFalse(self.store.settings()['check_config']['logging'])

    def test_clear_requires_strict_confirmation_and_preserves_other_state(self):
        self.log.record('audit','completed')
        history = self.store.root/'history.private.json'; history.write_bytes(b'KEEP_HISTORY')
        for value in (False,1,'true'):
            self.assertEqual(self.log.clear(value)['state'],'confirmation_required')
            self.assertTrue((self.log.root/FILES[1]).exists())
        self.assertEqual(self.log.clear(True)['state'],'completed')
        self.assertEqual(self.log.entries(),[]); self.assertEqual(history.read_bytes(),b'KEEP_HISTORY')

    def test_native_export_has_strict_confirmation_cancel_save_and_parameter_rejection(self):
        ops = Operations(self.store,self.home,discoverer=lambda:[])
        window = SimpleNamespace(create_file_dialog=Mock(return_value=None))
        ops.desktop_runtime = SimpleNamespace(window=window)
        for confirm in (False,1,'true'):
            self.assertEqual(ops.run('diagnostics-export',{},confirm)['state'],'confirmation_required')
        window.create_file_dialog.assert_not_called()
        with patch.dict('sys.modules',{'webview':SimpleNamespace(SAVE_DIALOG=30)}):
            self.assertEqual(ops.run('diagnostics-export',{},True)['state'],'cancelled')
            window.create_file_dialog.return_value = str(self.home/'export.zip')
            self.assertEqual(ops.run('diagnostics-export',{},True)['state'],'completed')
        self.assertTrue((self.home/'export.zip').is_file())
        with self.assertRaises(ValueError):ops.run('diagnostics-export',{'file':str(self.home/'other.zip')},True)
        self.assertFalse((self.home/'other.zip').exists())

    def test_native_write_validates_bytes_and_preserves_destination_if_changed(self):
        archive = self.log.archive(); path = self.home/'reviewed.zip'
        result = write_archive(path, archive)
        self.assertEqual(result['sha256'],archive['sha256'])
        with self.assertRaises(ValueError):write_archive(path,{**archive,'sha256':'0'*64})
        self.assertEqual(path.read_bytes(),base64.b64decode(archive['data']))
        self.assertEqual(list(self.home.glob('.envscope-diagnostics-*')),[])

    def test_memory_mode_never_touches_files(self):
        store = StateStore(self.home/'must-not-exist',memory=True); log = DiagnosticLog(store)
        log.record('audit','failed'); self.assertEqual(len(log.entries()),1)
        self.unpack(log.archive()); log.clear(True)
        self.assertFalse(store.root.exists())

    def test_unreadable_consent_never_reenables_logging_from_default_settings(self):
        self.store.save_settings({'check_config':{'logging':False}})
        (self.store.root/'settings.private.json').write_bytes(b'NOT_VALID_JSON')
        self.assertFalse(self.log.safe_record('audit','completed'))
        self.assertEqual(self.log.status()['state'],'unavailable')
        self.assertEqual(self.unpack(self.log.archive())['commands.jsonl'],b'')
        self.assertFalse(self.log.root.exists())

    def test_explicit_clear_can_remove_an_oversized_regular_log(self):
        self.log.record('audit','completed')
        with patch('envscope.diagnostics.LIMIT',1):
            self.assertFalse(self.log.safe_record('audit','completed'))
            self.assertEqual(self.log.clear(True)['state'],'completed')
        self.assertEqual(self.log.status()['state'],'ready')
        self.assertEqual(self.log.entries(),[])
