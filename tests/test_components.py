"""Owned data and injected OS adapters only; no installed legacy code executes."""
from copy import deepcopy
import base64
import json
import hashlib
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
import os
from unittest.mock import Mock, patch

from envscope.component_inventory import Layout, mac_definition, mac_snapshot, blocking, windows_definition, windows_snapshot, LABELS
from envscope.components_windows import WindowsComponents, MAX_ENCODED, MAX_COMMAND
from envscope.legacy_components import ComponentMigration
from envscope.state import StateStore

SID = 'S-1-5-21-100-200-300-1001'


def role():
    return {'id': 'guard', 'title': '旧版进程守护', 'label': 'ClaudeBodyguard', 'scope': 'user',
            'present': True, 'registered': True, 'owned': True, 'running': True, 'enabled': True,
            'definition': base64.b64encode(b'fixture definition').decode(), 'definition_sha': hashlib.sha256(b'fixture definition').hexdigest(),
            'script_sha': 'b'*64, 'principal_sid': SID, 'security': 'FIXTURE_ONLY'}


class ComponentsFixture:
    def __init__(self):
        self.rows = [role()]; self.receipt = {'state': 'not_configured', 'id': ''}; self.calls = []; self.fail = False
    def snapshot(self): return {'format': 1, 'system': 'Windows', 'actor': SID, 'rows': deepcopy(self.rows)}
    def status(self): return deepcopy(self.receipt)
    def execute(self, action, payload):
        self.calls.append((action, deepcopy(payload)))
        if self.fail:
            self.receipt = {'state': 'partial', 'id': payload['id'], 'actor': SID, 'roles': ['guard']}
            raise ValueError('fixture interrupted')
        if action == 'retire':
            self.original = deepcopy(self.rows)
            self.receipt = {'format': 1, 'state': 'committed', 'id': payload['id'], 'actor': SID, 'roles': ['guard'], 'original': deepcopy(self.rows)}
            self.rows[0].update(present=False, registered=False, enabled=False, running=False, definition=None, definition_sha=None, script_sha=None)
        else:
            self.rows = deepcopy(self.original); self.receipt['state'] = 'restored'


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve(); self.store = StateStore(self.home/'state')
        self.io = ComponentsFixture(); self.active = {}
        self.subject = ComponentMigration(self.store, self.home, io=self.io, replacements=lambda: self.active)

    def test_review_and_strict_consent_before_retire_preserve_account_data(self):
        account = self.home/'.claude-switcher/accounts/A'; account.mkdir(parents=True)
        file = account/'opaque.private.bin'; file.write_bytes(b'ENVSCOPE_FIXTURE_ONLY')
        plan = self.subject.prepare(['guard'])
        self.assertEqual(plan['state'], 'planned'); self.assertFalse(self.io.calls)
        self.assertEqual(self.subject.apply(plan['plan_id'], 'true')['state'], 'confirmation_required')
        self.assertEqual(self.subject.apply(plan['plan_id'], True)['state'], 'completed')
        self.assertEqual(file.read_bytes(), b'ENVSCOPE_FIXTURE_ONLY')
        self.assertTrue(self.subject.status(True)['can_restore']); self.assertFalse(blocking(self.io.snapshot()))

    def test_compare_changed_identity_and_receipt_before_any_write(self):
        for change in ('script', 'receipt', 'disabled'):
            with self.subTest(change=change):
                io = ComponentsFixture(); subject = ComponentMigration(self.store, self.home, io=io)
                plan = subject.prepare()
                if change == 'script': io.rows[0]['script_sha'] = 'c'*64
                if change == 'receipt': io.receipt['id'] = 'd'*32
                if change == 'disabled': io.rows[0]['enabled'] = False
                self.assertEqual(subject.apply(plan['plan_id'], True)['state'], 'retest_required'); self.assertFalse(io.calls)

    def test_unknown_foreign_or_permission_denied_never_becomes_removal_authority(self):
        for change in ({'owned': False}, {'present': None}, {'error': 'permission_denied'}):
            io = ComponentsFixture(); io.rows[0].update(change)
            subject = ComponentMigration(self.store, self.home, io=io)
            self.assertEqual(subject.prepare(['guard'])['state'], 'guided')
            self.assertTrue(blocking(io.snapshot()))
        self.assertTrue(blocking(None))

    def test_restore_waits_for_replacement_shutdown_and_preserves_paused_state(self):
        self.io.rows[0].update(enabled=False, running=False)
        plan = self.subject.prepare(); self.subject.apply(plan['plan_id'], True)
        self.active['guard'] = True
        self.assertEqual(self.subject.prepare(restore=True)['state'], 'guided')
        self.active.clear(); plan = self.subject.prepare(restore=True)
        self.assertEqual(self.subject.apply(plan['plan_id'], True)['state'], 'restored')
        self.assertFalse(self.io.rows[0]['enabled']); self.assertFalse(self.io.rows[0]['running'])

    def test_late_replacement_start_and_pending_recovery_block_new_work(self):
        plan = self.subject.prepare(); self.subject.apply(plan['plan_id'], True)
        plan = self.subject.prepare(restore=True); self.active['guard'] = True
        self.assertEqual(self.subject.apply(plan['plan_id'], True)['state'], 'retest_required')
        self.io.receipt['state'] = 'partial'
        self.assertEqual(self.subject.prepare()['state'], 'guided')

    def test_interruption_retains_recovery_and_stale_or_missing_token_is_not_consent(self):
        plan = self.subject.prepare(); self.io.fail = True
        value = self.subject.apply(plan['plan_id'], True)
        self.assertEqual(value['state'], 'partial'); self.assertTrue(value['recovery']['needs_recovery'])
        self.assertEqual(self.subject.apply('missing', True)['state'], 'retest_required')

    def test_generated_windows_code_is_bounded_fixed_and_no_user_script_runs_elevated(self):
        io = WindowsComponents(self.home, runner=Mock(), executable='powershell.exe'); io.actor = SID
        body = io._body('retire', input_path='C:/fixture/plan.private.bin', sha='e'*64)
        encoded = base64.b64encode('\n'.join(s.lstrip() for s in body.splitlines() if s.strip()).encode('utf-16-le'))
        self.assertLess(len(encoded), MAX_ENCODED)
        self.assertIn('PSModulePath', body); self.assertIn('RegisterTask(', body); self.assertIn('DeleteTask(', body)
        self.assertNotIn('Invoke-Expression', body); self.assertNotIn('Remove-Item -Recurse', body)
        self.assertNotIn('Stop-Process', body); self.assertNotIn('Set-TimeZone', body)
        if os.name=='nt':
            home=Path('C:/Users/runneradmin/AppData/Local/Temp/envscope-components-fixture-12345678')
            layout=Layout(home,'Windows',fixture={'root':home/'privileged/receipt','task':'EnvScopeLegacyFixture'+'1'*32,
                'labels':{},'daemons':home/'unused','scripts':home/'unused'})
            value=WindowsComponents(home,layout=layout);value.actor='S-1-5-21-3776380004-1005456608-3524014338-500'
            body=value._body('restore',input_path='C:/Users/runneradmin/AppData/Local/Temp/envscope-components-plan-12345678/plan.private.bin',sha='a'*64)
            payload=base64.b64encode('\n'.join(s.lstrip() for s in body.splitlines() if s.strip()).encode('utf-16-le')).decode()
            self.assertLessEqual(len(payload),MAX_ENCODED)
            self.assertLessEqual(len(subprocess.list2cmdline([value.executable,'-NoProfile','-NonInteractive','-EncodedCommand',payload])),MAX_COMMAND)
            self.assertLess(MAX_COMMAND+1,32767)

    @unittest.skipUnless(os.name=='nt','Windows descriptor math only; no jobs or filesystem ACLs change')
    def test_descriptor_math_preserves_meaning_and_rejects_real_permission_changes(self):
        from envscope.components_windows import TRANSACTION
        from envscope.system_network_windows import powershell
        source=TRANSACTION[TRANSACTION.index('function xS('):TRANSACTION.index('function Same(')]
        source+="""
$before='O:BAG:SYD:(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;;FR;;;BU)'
$after='O:BAG:SYD:AI(A;;FR;;;BU)(A;ID;FA;;;BA)(A;ID;FA;;;SY)'
$deny='O:BAG:SYD:(D;;FW;;;BU)(A;;FR;;;BU)'
@{equivalent=((xS $before) -ceq (xS $after));
 wider=((xS $before) -ceq (xS $after.Replace('FR;;;BU','FA;;;BU')));
 owner=((xS $before) -ceq (xS $after.Replace('O:BA','O:SY')));
 protected=((xS $before) -ceq (xS $after.Replace('D:AI','D:PAI')));
 inherited=((xS $before) -ceq (xS $after.Replace('A;ID;FA;;;SY','A;;FA;;;SY')));
 deny=((xS $deny) -ceq (xS 'O:BAG:SYD:(A;;FR;;;BU)(D;;FW;;;BU)'))}|ConvertTo-Json -Compress
"""
        encoded=base64.b64encode(source.encode('utf-16-le')).decode()
        value=subprocess.run([powershell(),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,timeout=30)
        self.assertEqual(value.returncode,0,value.stderr.decode(errors='replace'))
        self.assertEqual(json.loads(value.stdout.decode('utf-8-sig')),
                         {'equivalent':True,'wider':False,'owner':False,'protected':False,'inherited':False,'deny':False})

    def test_mac_definition_rejects_wrong_owner_command_extra_environment_and_domain(self):
        layout = Layout(self.home, 'Darwin')
        original = {'Label': LABELS['guard'], 'ProgramArguments': ['/bin/bash', str(layout.script('guard'))], 'StartInterval': 10, 'RunAtLoad': True}
        mac_definition(plistlib.dumps(original), 'guard', layout)
        for change in ({'ProgramArguments': ['/bin/bash', '/tmp/foreign.sh']}, {'UserName': 'other'}, {'EnvironmentVariables': {'BASH_ENV': '/tmp/foreign'}}):
            with self.assertRaises(ValueError): mac_definition(plistlib.dumps({**original, **change}), 'guard', layout)

    def test_no_legacy_code_exec_on_mac_read_and_registered_without_definition_is_conflict(self):
        layout = Layout(self.home, 'Darwin', fixture={'root': self.home/'receipt', 'task': 'fixture',
            'labels': LABELS, 'daemons': self.home/'daemons', 'scripts': self.home/'scripts'})
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, b'opaque present', b''))
        value = mac_snapshot(layout, 501, jobs=Mock(), runner=runner, roles=['guard'])
        self.assertFalse(value['rows'][0]['owned']); self.assertTrue(blocking(value))
        self.assertEqual(runner.call_args.args[0][:2], ['/bin/launchctl', 'print'])


if __name__ == '__main__': unittest.main()
