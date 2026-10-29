"""Injected OS state only; no privileged command, scheduler or account runs."""
import base64
import copy
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import plistlib
import re
import tempfile
import unittest
from unittest.mock import Mock

from envscope import __release__
from envscope.maintenance import Maintenance
from envscope.region_profiles import profile
from envscope.region_setup import RegionSetup
from envscope.state import StateStore
from envscope.target_environment import fingerprint
from envscope.timezone_service import TimezoneService
from envscope.watchdog import Watchdog
from tests.test_timezone_service import FixtureIO


class FakeScheduler:
    def __init__(self):self.definition=None;self.calls=[];self.fail=False
    def build(self,interval):return {'system':'fixture','body':'fixture '+str(interval),'interval':interval}
    def inspect(self,spec=None):
        present=self.definition is not None;owned=present and spec==self.definition
        return {'present':present,'owned':owned,'registered':owned,'state':'registered' if owned else 'missing'}
    def install(self,spec,previous=None):
        self.calls.append(('install',spec))
        if self.fail:raise ValueError('fixture registration failure')
        self.definition=spec
    def remove(self,spec):self.calls.append(('remove',spec));self.definition=None


class TransactionFixture(FixtureIO):
    def __init__(self,inventory):
        super().__init__()
        self.value['outcome']={}
        self.inventory=inventory;self.backups={};self.cancel=False;self.interrupt=False

    def execute(self,script):
        self.scripts.append(script)
        if self.cancel:raise ValueError('fixture authorization cancelled')
        match=re.search(r'/usr/bin/printf %s ([A-Za-z0-9+/=]+) \| /usr/bin/base64 -D > "\$PENDING/receipt.plist"',script)
        if match:
            receipt=plistlib.loads(base64.b64decode(match[1]));nonce=receipt['nonce']
            self.backups[nonce]=copy.deepcopy(self.value)
            self.value.update(transaction=receipt,outcome={'format':1,'nonce':nonce,'state':'committed'},pending=False)
            if self.interrupt:
                self.value.update(pending=True,outcome={})
                raise ValueError('fixture interrupted before mutation')
            if receipt['operation']=='install':
                self.value.update(baseline={'format':1,'target':receipt['target'],'original':receipt['original'],
                                           'owner_uid':501,'release':__release__},registered=True,
                                  hashes={'worker':'a'*64,'baseline.plist':hashlib.sha256(receipt['target'].encode()).hexdigest(),'daemon':'c'*64})
                self.inventory['timezone_iana']=receipt['target']
                self.value['status']={'format':1,'release':__release__,'state':'healthy','at_epoch':self.clock(),
                                      'target':receipt['target'],'observed':receipt['target'],'fixture':False,'initial':False}
            else:
                self.value.update(baseline={},registered=False,hashes={'worker':None,'baseline.plist':None,'daemon':None})
                if 'restore_clock=1\n"$PENDING/rollback-worker" --restore-zone' in script:
                    self.inventory['timezone_iana']=receipt['original']
        else:
            receipt=copy.deepcopy(self.value['transaction']);nonce=receipt['nonce']
            self.value=copy.deepcopy(self.backups[nonce])
            self.value.update(transaction=receipt,outcome={'format':1,'nonce':nonce,'state':'restored'},pending=False)
            self.inventory['timezone_iana']=receipt['before']


class TimezoneIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name).resolve();self.store=StateStore(self.home/'state')
        self.inventory={'timezone_iana':'America/New_York','locale':'en-US'}
        self.io=TransactionFixture(self.inventory)
        self.root=TimezoneService(self.store,lambda:self.inventory,system='Darwin',io=self.io,uid=501)
        self.writer=Mock(side_effect=lambda k,v:self.inventory.update({k if k=='locale' else 'timezone_iana':v}))
        self.region=RegionSetup(self.store,lambda:self.inventory,self.home,'Darwin',self.writer,timezone_service=self.root)
        self.scheduler=FakeScheduler()
        guard=Watchdog(self.home,system='Darwin',reader=lambda:self.inventory,writer=self.writer,authority=self.io.inspect)
        self.maintenance=Maintenance(self.store,scheduler=self.scheduler,home=self.home,watchdog=guard,timezone_service=self.root)
        self.choose('us-new-york')

    def choose(self,city):
        p=profile(city,'Darwin')
        self.store.save_settings({'usage':'desktop','connection_mode':'direct','usage_country':'US','region_profile':city,
                                 **{k:p[k] for k in ('country','timezone','locale')}},confirm_environment=True)
        self.report={'report_id':'report-'+city,'mode':'one-click-desktop','created_at':datetime.now(timezone.utc).isoformat(),
                     'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],
                     'environment':{'fingerprint':fingerprint(self.store.settings())}}

    def install(self):
        plan=self.root.prepare(self.report)
        self.assertEqual(self.root.apply(plan['plan_id'],True)['state'],'completed')
        return plan

    def test_one_confirmation_enables_system_timezone_and_user_checks(self):
        plan=self.maintenance.prepare(self.report,5,watchdog={'timezone':True})
        self.assertEqual(plan['state'],'planned')
        self.assertTrue(any('管理员授权' in e for e in plan['effects']))
        self.assertFalse(self.io.scripts);self.assertFalse(self.scheduler.calls)
        for confirm in (False,1,'true'):
            self.assertEqual(self.maintenance.enable(plan['plan_id'],self.report,confirm)['state'],'confirmation_required')
        self.assertEqual(self.maintenance.enable(plan['plan_id'],self.report,True)['state'],'enabled')
        self.assertTrue(self.root.status()['installed'])
        self.assertEqual(self.maintenance._config()['watchdog']['timezone'],'America/New_York')
        self.assertNotIn('timezone_plan',self.maintenance._config())
        self.assertEqual(len(self.io.scripts),1)

    def test_scheduler_failure_rolls_back_new_system_component(self):
        self.scheduler.fail=True
        plan=self.maintenance.prepare(self.report,5,watchdog={'timezone':True})
        result=self.maintenance.enable(plan['plan_id'],self.report,True)
        self.assertEqual(result['state'],'failed')
        self.assertEqual(result['timezone_service']['state'],'completed')
        self.assertFalse(self.root.status()['installed'])
        self.assertFalse(self.maintenance._config()['enabled'])
        self.assertEqual(len(self.io.scripts),2)

    def test_cancelled_authorization_does_not_register_user_task(self):
        plan=self.maintenance.prepare(self.report,5,watchdog={'timezone':True})
        self.io.cancel=True
        result=self.maintenance.enable(plan['plan_id'],self.report,True)
        self.assertEqual(result['state'],'partial')
        self.assertFalse(self.scheduler.calls)
        self.assertFalse(self.maintenance._config().get('enabled'))

    def test_target_change_and_restart_undo_restore_old_guard_together(self):
        self.install();old_hashes=copy.deepcopy(self.io.value['hashes'])
        self.choose('us-los-angeles')
        plan=self.region.prepare(self.report,['timezone'])
        self.assertEqual(plan['state'],'planned')
        self.assertTrue(any('同步更新' in e for e in plan['effects']))
        self.assertEqual(self.region.apply(plan['plan_id'],self.report,True)['state'],'completed')
        self.assertEqual(self.inventory['timezone_iana'],'America/Los_Angeles')
        self.assertEqual(self.io.value['baseline']['target'],'America/Los_Angeles')
        restarted=RegionSetup(self.store,lambda:self.inventory,self.home,'Darwin',self.writer,timezone_service=self.root)
        self.assertEqual(restarted.undo(True)['state'],'completed')
        self.assertEqual(self.io.value['baseline']['target'],'America/New_York')
        self.assertEqual(self.inventory['timezone_iana'],'America/New_York')
        self.assertEqual(self.io.value['hashes'],old_hashes)
        self.writer.assert_not_called()

    def test_guard_updates_even_when_clock_already_matches_new_target(self):
        self.install();self.choose('us-los-angeles');self.inventory['timezone_iana']='America/Los_Angeles'
        plan=self.region.prepare(self.report,['timezone'])
        self.assertEqual(plan['state'],'planned')
        self.assertEqual(self.region.apply(plan['plan_id'],self.report,True)['state'],'completed')
        self.assertEqual(self.io.value['baseline']['target'],'America/Los_Angeles')
        self.assertEqual(self.region.undo(True)['state'],'completed')
        self.assertEqual(self.io.value['baseline']['target'],'America/New_York')

    def test_later_system_service_transaction_is_never_overwritten_by_region_undo(self):
        self.install();self.choose('us-los-angeles')
        plan=self.region.prepare(self.report,['timezone']);self.region.apply(plan['plan_id'],self.report,True)
        self.install();count=len(self.io.scripts)
        self.assertEqual(self.region.undo(True)['state'],'partial')
        self.assertEqual(len(self.io.scripts),count)

    def test_unexecuted_native_plan_can_be_cleared_without_system_authorization(self):
        self.install();self.choose('us-los-angeles')
        plan=self.region.prepare(self.report,['timezone']);self.io.cancel=True
        self.assertEqual(self.region.apply(plan['plan_id'],self.report,True)['state'],'partial')
        count=len(self.io.scripts)
        self.assertEqual(self.region.undo(True)['state'],'completed')
        self.assertEqual(len(self.io.scripts),count)

    def test_undo_requires_fresh_state_and_restores_uninstalled_service(self):
        self.install()
        plan=self.root.prepare(None,remove=True,restore=True)
        self.assertEqual(self.root.apply(plan['plan_id'],True)['state'],'completed')
        self.assertTrue(self.root.status()['can_undo'])
        undo=self.root.prepare_undo()
        for confirm in (False,1,'true'):self.assertEqual(self.root.undo(undo['plan_id'],confirm)['state'],'confirmation_required')
        self.inventory['timezone_iana']='Europe/London'
        count=len(self.io.scripts)
        self.assertEqual(self.root.undo(undo['plan_id'],True)['state'],'retest_required')
        self.assertEqual(len(self.io.scripts),count)
        undo=self.root.prepare_undo()
        self.assertEqual(self.root.undo(undo['plan_id'],True)['state'],'completed')
        self.assertTrue(self.root.status()['installed'])
        self.assertFalse(self.root.status()['can_undo'])


if __name__=='__main__':unittest.main()
