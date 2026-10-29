import copy
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import plistlib
import unittest
from unittest.mock import Mock,patch

from envscope import __release__
from envscope.state import StateStore
from envscope.timezone_service import TimezoneService,NativeTimezoneIO,Layout,daemon_bytes,render_transaction,render_recovery
from envscope.target_environment import fingerprint


class FixtureIO:
    def __init__(self):
        self.layout=Layout();self.fixture=False;self.now=1000;self.clock=lambda:self.now
        self.value={'hashes':{'worker':None,'baseline.plist':None,'daemon':None},'baseline':{},'status':{},'transaction':{},'registered':False,'pending':False}
        self.binary={'path':"/Users/fixture/app's folder/$(touch NEVER)/timezone-helper",'sha256':'a'*64,'release':__release__}
        self.worker=lambda:dict(self.binary)
        self.scripts=[];self.effect=None
    def inspect(self):return copy.deepcopy(self.value)
    def execute(self,script):
        self.scripts.append(script)
        if self.effect:self.effect()


class TimezoneServiceTests(unittest.TestCase):
    def setUp(self):
        self.store=StateStore(memory=True)
        self.store.save_settings({'usage':'desktop','connection_mode':'direct','usage_country':'US','country':'US','region_profile':'us-new-york',
                                  'timezone':'America/New_York','locale':'en-US'},confirm_environment=True)
        self.io=FixtureIO();self.zone='Asia/Shanghai'
        self.service=TimezoneService(self.store,lambda:{'timezone_iana':self.zone},system='Darwin',io=self.io,uid=501)
        self.report={'report_id':'fixture-report','mode':'one-click-desktop','created_at':datetime.now(timezone.utc).isoformat(),
                     'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],
                     'environment':{'fingerprint':fingerprint(self.store.settings())}}
    def installed(self):
        self.io.value.update(hashes={'worker':'a'*64,'baseline.plist':'b'*64,'daemon':'c'*64},
          baseline={'format':1,'target':'America/New_York','original':'Asia/Shanghai','owner_uid':501,'release':__release__},registered=True)
    def test_requires_fresh_region_evidence_and_explicit_preset(self):
        self.assertEqual(self.service.prepare(None)['state'],'retest_required')
        bad=copy.deepcopy(self.report);bad['findings'][0]['status']='fail'
        self.assertEqual(self.service.prepare(bad)['state'],'retest_required')
        self.store.save_settings({'timezone':'Etc/UTC'},confirm_environment=True)
        self.report['environment']['fingerprint']=fingerprint(self.store.settings())
        self.assertEqual(self.service.prepare(self.report)['state'],'guided')
        self.assertFalse(self.io.scripts)
    def test_install_requires_boolean_true(self):
        plan=self.service.prepare(self.report)
        self.assertEqual(plan['state'],'planned')
        for confirmed in (False,1,'true'):
            self.assertEqual(self.service.apply(plan['plan_id'],confirmed)['state'],'confirmation_required')
        self.assertFalse(self.io.scripts)
        self.io.effect=self.installed
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'completed')
        script=self.io.scripts[0]
        self.assertIn('rollback()',script)
        self.assertNotIn('/bin/bash',script)
        self.assertIn('"$ROOT/worker" --initial-apply',script)
        self.assertIn('stop_job',script)
        self.assertNotIn('sudoers',script)
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'retest_required')
    def test_heartbeat_refresh_does_not_invalidate_config_plan(self):
        self.installed();plan=self.service.prepare(self.report)
        self.io.value['status']={'at_epoch':1000,'state':'healthy'}
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'completed')
    def test_changes_in_timezone_baseline_or_binary_stop_old_plan(self):
        for change in ('timezone','settings','binary','service'):
            with self.subTest(change=change):
                self.setUp();plan=self.service.prepare(self.report)
                if change=='timezone':self.zone='Europe/London'
                elif change=='settings':self.store.save_settings({'timezone':'Etc/UTC'})
                elif change=='binary':self.io.binary['sha256']='b'*64
                else:self.io.value['registered']=True
                self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'retest_required')
                self.assertFalse(self.io.scripts)
    def test_status_requires_real_fresh_scheduled_heartbeat(self):
        self.installed()
        self.assertEqual(self.service.status()['state'],'waiting')
        self.io.value['status']={'format':1,'release':__release__,'at_epoch':1000,'state':'healthy','target':'America/New_York','observed':'America/New_York','fixture':False,'initial':True}
        self.assertEqual(self.service.status()['state'],'waiting')
        self.io.value['status']['initial']=False
        self.assertEqual(self.service.status()['state'],'active')
        self.io.value['status']['at_epoch']=0
        self.assertEqual(self.service.status()['state'],'waiting')
        self.io.value['status']['at_epoch']=1001
        self.assertEqual(self.service.status()['state'],'waiting')
        self.io.value['status']['at_epoch']=1000;self.io.value['status']['state']='paused'
        self.assertEqual(self.service.status()['state'],'attention')
    def test_uninstall_does_not_require_eligible_country(self):
        self.installed();self.store.save_settings({'usage_country':'CN'})
        plan=self.service.prepare(None,remove=True,restore=True)
        self.assertEqual(plan['state'],'planned')
        self.assertTrue(any('Asia/Shanghai' in effect for effect in plan['effects']))
        self.io.effect=lambda:self.io.value.update(baseline={},hashes={'worker':None,'baseline.plist':None,'daemon':None},registered=False)
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'completed')
    def test_other_users_and_invalid_boolean_cannot_overwrite(self):
        self.installed();self.io.value['baseline']['owner_uid']=502
        self.assertEqual(self.service.prepare(self.report)['state'],'blocked')
        self.assertEqual(self.service.prepare(None,remove=True)['state'],'blocked')
        with self.assertRaises(ValueError):self.service.prepare(self.report,remove='true')
    def test_previous_region_pass_never_authorizes_changed_or_unsupported_location(self):
        for country in ('CN','RU','US'):
            self.store.save_settings({'usage_country':country,'locale':'en-GB'})
            self.assertEqual(self.service.prepare(self.report)['state'],'retest_required')
        self.assertFalse(self.io.scripts)
    def test_interruption_has_explicit_reviewed_recovery(self):
        snapshot=self.io.inspect();snapshot['observed']=self.zone
        _,receipt=render_transaction(self.io.layout,snapshot,self.io.binary,'install','America/New_York',501)
        self.io.value.update(pending=True,transaction=receipt)
        self.assertEqual(self.service.status()['state'],'recovery_required')
        plan=self.service.prepare_recovery();self.assertEqual(plan['state'],'planned')
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'retest_required')
        for confirm in (False,1,'true'):self.assertEqual(self.service.recover(plan['plan_id'],confirm)['state'],'confirmation_required')
        self.io.effect=lambda:self.io.value.update(pending=False)
        self.assertEqual(self.service.recover(plan['plan_id'],True)['state'],'completed')
        self.assertIn('--restore-zone Asia/Shanghai',self.io.scripts[-1])
    def test_cancelled_or_failed_authorization_preserves_recovery(self):
        plan=self.service.prepare(self.report)
        def fail():
            self.io.value['pending']=True
            raise ValueError('fixture authorization failure')
        self.io.effect=fail
        result=self.service.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'partial')
        self.assertEqual(result['status']['state'],'recovery_required')
    def test_windows_has_no_system_service_side_effect(self):
        self.service.system='Windows'
        self.assertEqual(self.service.prepare(self.report)['state'],'not_applicable')
        self.assertFalse(self.io.scripts)
    def test_native_authorization_never_receives_admin_password(self):
        runner=Mock(return_value=Mock(returncode=0))
        io=NativeTimezoneIO(runner=runner,worker=lambda:self.io.binary)
        io.execute("/usr/bin/printf '%s' 'fixture-only'")
        argv=runner.call_args.args[0]
        self.assertEqual(argv[:2],['/usr/bin/osascript','-e'])
        self.assertIn('with administrator privileges',argv[2])
        self.assertIn('--lifecycle',argv[2])
        self.assertNotIn('password ',argv[2])
    def test_fixed_daemon_command_has_no_user_profile_paths(self):
        value=plistlib.loads(daemon_bytes(Layout()))
        self.assertEqual(value['ProgramArguments'],[str(Layout().root/'worker'),'--once'])
        self.assertEqual(value['StartInterval'],60)
        self.assertFalse(any('/Users/' in arg for arg in value['ProgramArguments']))


if __name__=='__main__':unittest.main()
