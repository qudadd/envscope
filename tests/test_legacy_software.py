"""Disposable program files and injected jobs only; no vendor code executes."""
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.legacy_components import ComponentMigration
from envscope.legacy_software import SoftwareCleanup, layout, signature, rename_exclusive, recognized
from envscope.state import StateStore
from tests.test_components import ComponentsFixture


class SoftwareTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name).resolve();self.store=StateStore(self.home/'state')
        self.jobs=ComponentsFixture();self.components=ComponentMigration(self.store,self.home,io=self.jobs)
        self.processes=Mock(return_value=False);self.pending=[]
        self.subject=SoftwareCleanup(self.home,self.components,system='Windows',processes=self.processes,pending=lambda:self.pending)
        self.core=self.subject.paths['core'];self.core.parent.mkdir()
        self.core.write_text('# claude-switch.ps1 checkdetail\n# SELF AUTHORED INERT FIXTURE\n')
        self.ui=self.subject.paths['ui'];self.ui.write_text('# claude-switcher Window\n# SELF AUTHORED INERT FIXTURE\n')
        self.account=self.core.parent/'accounts/A/opaque.private.bin';self.account.parent.mkdir(parents=True)
        self.account.write_bytes(b'ACCOUNT_FIXTURE_ONLY')

    def prepare(self,roles=None,**kwargs):
        plan=self.subject.prepare(roles if kwargs.get('restore') else roles or ['core','ui'],**kwargs)
        self.assertEqual(plan['state'],'planned',plan)
        return plan

    def apply(self,plan):
        return self.subject.apply(plan['plan_id'],True)

    def test_read_only_selection_consent_stop_jobs_and_restore_preserve_accounts(self):
        before=signature(self.core);self.subject.status()
        self.assertFalse(self.subject.root.exists());self.assertFalse(self.jobs.calls)
        plan=self.prepare(['core'])
        self.assertFalse(self.jobs.calls)
        for confirmed in (False,'true',1,None):
            self.assertEqual(self.subject.apply(plan['plan_id'],confirmed)['state'],'confirmation_required')
        result=self.apply(plan);self.assertEqual(result['state'],'completed',result)
        self.assertEqual(self.jobs.calls[0][0],'retire');self.assertFalse(self.core.exists());self.assertTrue(self.ui.exists())
        self.assertEqual(self.account.read_bytes(),b'ACCOUNT_FIXTURE_ONLY')
        record=self.subject._record();backup=self.subject._backup(self.core,record['id'],'core')
        self.assertEqual(signature(backup),before)
        self.subject=SoftwareCleanup(self.home,self.components,system='Windows',processes=self.processes)
        restore=self.prepare(restore=True);self.assertEqual(self.apply(restore)['state'],'restored')
        self.assertEqual(signature(self.core),before);self.assertFalse(backup.exists())
        self.assertEqual(len(self.jobs.calls),1,'Restoring program files never restarts old jobs')

    def test_changed_file_receipt_or_permissions_cannot_use_stale_plan(self):
        for change in ('file','job','process','pending'):
            with self.subTest(change=change):
                plan=self.prepare()
                if change=='file':self.core.write_text('# claude-switch changed checkdetail')
                elif change=='job':self.jobs.rows[0]['enabled']=False
                elif change=='process':self.processes.return_value=True
                else:self.pending.append('accounts/A.previous')
                value=self.apply(plan)
                self.assertIn(value['state'],('retest_required','guided'))
                self.assertTrue(self.core.exists());self.assertFalse(self.jobs.calls)
                self.processes.return_value=False;self.pending.clear()

    def test_manual_unknown_files_and_unknown_jobs_are_never_auto_cleaned(self):
        self.ui.write_text('FOREIGN FIXTURE')
        rows={r['id']:r for r in self.subject.status()['rows']}
        self.assertFalse(rows['ui']['eligible']);self.assertEqual(self.subject.prepare(['ui'])['state'],'guided')
        self.assertTrue(self.ui.exists())
        self.jobs.rows[0]['error']='permission_denied'
        self.assertEqual(self.subject.prepare(['core'])['state'],'guided');self.assertFalse(self.jobs.calls)
        for roles in ([{}],['core','core'],['../accounts'],['system.core'],'core'):
            self.assertIn(self.subject.prepare(roles)['state'],('guided','not_needed'))

    def test_interrupted_move_keeps_journal_restart_restores_all_files(self):
        move=rename_exclusive;calls=[]
        def fail_second(source,destination):
            calls.append(source)
            if len(calls)==2:raise OSError('owned fixture interruption')
            move(source,destination)
        plan=self.prepare()
        with patch('envscope.legacy_software.rename_exclusive',side_effect=fail_second):value=self.apply(plan)
        self.assertEqual(value['state'],'partial',value);self.assertFalse(self.core.exists());self.assertTrue(self.ui.exists())
        self.assertEqual(self.subject.prepare(['ui'])['state'],'guided')
        self.subject=SoftwareCleanup(self.home,self.components,system='Windows',processes=self.processes)
        plan=self.prepare(restore=True);self.assertEqual(self.apply(plan)['state'],'restored')
        self.assertTrue(self.core.exists());self.assertTrue(self.ui.exists());self.assertEqual(len(self.jobs.calls),1)
        logs=''.join(p.read_text(encoding='utf-8') for p in (self.subject.root/'events').glob('*.jsonl'))
        self.assertNotIn('SELF AUTHORED',logs);self.assertNotIn('ACCOUNT_FIXTURE_ONLY',logs)

    def test_new_installation_and_changed_backup_are_never_overwritten(self):
        self.assertEqual(self.apply(self.prepare(['core']))['state'],'completed')
        self.core.write_text('NEW INSTALLATION FIXTURE')
        plan=self.prepare(restore=True);value=self.apply(plan)
        self.assertEqual(value['state'],'partial');self.assertEqual(self.core.read_text(),'NEW INSTALLATION FIXTURE')
        record=self.subject._record();backup=self.subject._backup(self.core,record['id'],'core')
        self.assertTrue(backup.exists())
        self.core.unlink();backup.write_text('TAMPERED FIXTURE')
        plan=self.prepare(restore=True);self.assertEqual(self.apply(plan)['state'],'partial');self.assertFalse(self.core.exists())

    def test_rename_never_overwrites_an_existing_destination(self):
        other=self.core.with_name('owned-existing');other.write_bytes(b'PRESERVE')
        with self.assertRaises(OSError):rename_exclusive(self.core,other)
        self.assertTrue(self.core.exists());self.assertEqual(other.read_bytes(),b'PRESERVE')

    def test_job_failure_stops_before_moving_programs_and_can_recover(self):
        self.jobs.fail=True;value=self.apply(self.prepare())
        self.assertEqual(value['state'],'partial');self.assertTrue(self.core.exists());self.assertTrue(self.ui.exists())
        # Files can be restored only after the ambiguous task transaction is
        # manually resolved; never guess that a still-present task is stopped.
        self.assertEqual(self.subject.prepare(restore=True)['state'],'planned')
        self.assertEqual(self.apply(self.prepare(restore=True))['state'],'partial')
        self.assertTrue(self.account.exists())

    def test_account_transaction_and_unreadable_processes_block_before_any_write(self):
        for state in (True,None):
            self.processes.return_value=state
            self.assertEqual(self.subject.prepare(['core'])['state'],'guided')
        self.processes.return_value=False;self.pending.append('profile/Claude.new')
        self.assertEqual(self.subject.prepare(['core'])['state'],'guided')
        self.assertFalse(self.subject.root.exists());self.assertFalse(self.jobs.calls)

    def test_review_can_stop_owned_job_but_manual_script_blocks_file_move(self):
        guard=self.subject.paths['guard'];guard.write_text('# Claude PROXY_MODE SELF AUTHORED FIXTURE\n')
        self.jobs.rows[0]['script']=str(guard)
        self.processes.side_effect=lambda paths:True if guard in paths else False
        plan=self.subject.prepare(['guard'])
        self.assertEqual(plan['state'],'planned',plan)
        value=self.apply(plan)
        self.assertEqual(value['state'],'partial',value)
        self.assertEqual(self.jobs.calls[0][0],'retire')
        self.assertTrue(guard.exists(),'A manual process left after stopping the job must retain its file')

    def test_plan_expiry_including_slow_recheck_never_retires_tasks(self):
        clock=[1.];self.subject.clock=lambda:clock[0]
        plan=self.prepare();clock[0]=92
        self.assertEqual(self.apply(plan)['state'],'retest_required')
        clock[0]=100;plan=self.prepare()
        def slow(*args):clock[0]=192;return False
        self.processes.side_effect=slow
        self.assertEqual(self.apply(plan)['state'],'retest_required');self.assertFalse(self.jobs.calls)

    def test_hardlinks_and_symlinks_are_preserved(self):
        link=self.core.with_name('shared');os.link(self.core,link)
        self.assertEqual(self.subject.prepare(['core'])['state'],'guided')
        self.assertTrue(self.core.exists());self.assertTrue(link.exists())
        link.unlink()
        outer=self.home/'foreign';outer.write_bytes(b'PRESERVE')
        target=self.subject.paths['guard']
        try:target.symlink_to(outer)
        except OSError:return
        self.assertEqual(self.subject.prepare(['guard'])['state'],'guided');self.assertEqual(outer.read_bytes(),b'PRESERVE')

    def test_malformed_restore_record_cannot_choose_arbitrary_paths(self):
        self.assertEqual(self.apply(self.prepare(['core']))['state'],'completed')
        path=self.subject.root/'latest.private.json';value=json.loads(path.read_text())
        value['rows'][0]['id']='../accounts';path.write_text(json.dumps(value))
        self.assertEqual(self.subject.status()['state'],'invalid');self.assertEqual(self.subject.prepare(restore=True)['state'],'guided')
        self.assertTrue(self.account.exists())

    def test_macos_app_and_template_data_are_recognized_without_execution(self):
        paths=layout(self.home,'Darwin');app=paths['app'];(app/'Contents/MacOS').mkdir(parents=True)
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.claude-switcher','CFBundleExecutable':'ClaudeSwitcher'}))
        (app/'Contents/MacOS/ClaudeSwitcher').write_bytes(b'INERT NO EXECUTABLE FIXTURE')
        self.assertTrue(recognized(app,'app','Darwin',self.home))
        original=signature(app);backup=app.with_name('moved.app');rename_exclusive(app,backup);self.assertEqual(signature(backup),original)
        (backup/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'foreign','CFBundleExecutable':'ClaudeSwitcher'}))
        self.assertFalse(recognized(backup,'app','Darwin',self.home))

    @unittest.skipUnless(__import__('platform').system()=='Darwin','macOS native compiler')
    def test_native_program_helper_builds_and_rejects_unbound_operation(self):
        from scripts.build_timezone_worker import build
        import subprocess
        labels={'GUARD':'fixture.guard','TIMEZONE':'fixture.timezone','UPDATE':'fixture.update','USER':'fixture.user'}
        values={'ENVSCOPE_COMPONENT_ROOT':str(self.home/'native/receipt'),'ENVSCOPE_COMPONENT_SOURCE':str(self.home/'native/scripts'),
                'ENVSCOPE_COMPONENT_DAEMONS':str(self.home/'native/daemons'),'ENVSCOPE_COMPONENT_HOME':str(self.home)}
        values.update({'ENVSCOPE_COMPONENT_LABEL_'+k:v for k,v in labels.items()})
        header=self.home/'fixture.h';header.write_text('\n'.join('#define '+k+' '+json.dumps(v) for k,v in values.items())+'\n#define ENVSCOPE_COMPONENT_FIXTURE 1\n')
        folder=build(self.home/'compiled',header,component='components')
        binary=folder/'components-helper'
        self.assertTrue(json.loads(subprocess.check_output([str(binary),'--version']))['fixture'])
        value=subprocess.run([str(binary),'--retire-files'],capture_output=True,timeout=5)
        self.assertNotEqual(value.returncode,0);self.assertFalse((self.home/'native').exists())

    @unittest.skipUnless(os.name=='nt','Windows shell links and DACLs')
    def test_actual_shell_link_is_read_only_and_acl_changes_invalidate_plan(self):
        from envscope.system_network_windows import powershell,quote
        import subprocess
        path=self.subject.paths['shortcut'];path.parent.mkdir()
        args='-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+str(self.ui)+'"'
        command="$l=(New-Object -ComObject WScript.Shell).CreateShortcut("+quote(str(path))+");$l.TargetPath="+quote(powershell())+";$l.Arguments="+quote(args)+";$l.Save()"
        encoded=base64.b64encode(command.encode('utf-16-le')).decode('ascii')
        result=subprocess.run([powershell(),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        before=path.read_bytes();self.assertTrue(recognized(path,'shortcut','Windows',self.home));self.assertEqual(path.read_bytes(),before)
        self.assertEqual(self.apply(self.prepare(['shortcut']))['state'],'completed')
        self.assertFalse(path.exists());self.assertEqual(self.apply(self.prepare(restore=True))['state'],'restored')
        self.assertEqual(path.read_bytes(),before)
        # The program preview binds access rights as well as bytes. Only an
        # owned temporary file receives this additional read grant.
        plan=self.prepare(['core'])
        subprocess.run(['icacls.exe',str(self.core),'/grant','*S-1-1-0:R'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(self.apply(plan)['state'],'retest_required')


if __name__=='__main__':unittest.main()
