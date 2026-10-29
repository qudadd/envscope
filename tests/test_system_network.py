"""Network fixtures only. No real adapter, DNS cache, elevation or client runs."""
import copy
from datetime import datetime,timezone,timedelta
import json
import unittest

from envscope.state import StateStore
from envscope.system_network import SystemNetwork,validate_snapshot
from envscope.target_environment import fingerprint

A='11111111-1111-4111-8111-111111111111'
B='22222222-2222-4222-8222-222222222222'


class NetworkFixture:
    def __init__(self):
        self.value={'format':1,'owner':501,'adapters':[
            {'id':A,'name':'Active / 网卡','active':True,'ipv6_enabled':True,
             'config':{'ConfigMethod':'Manual','Addresses':['2001:db8::1'],'PrefixLength':[64],'Opaque':b'CF_DATA_FIXTURE'}},
            {'id':B,'name':'Inactive','active':False,'ipv6_enabled':True,'config':{'ConfigMethod':'Automatic'}}]}
        self.record={'state':'not_configured','id':''};self.calls=[];self.mutate=True
    def snapshot(self):return copy.deepcopy(self.value)
    def status(self):return copy.deepcopy(self.record)
    def execute(self,action,payload):
        self.calls.append((action,copy.deepcopy(payload)))
        if action=='apply':
            self.record={'id':payload['nonce'],'owner':payload['owner'],'state':'committed','adapters':copy.deepcopy(payload['adapters']),
                         'dns_flush':'completed' if payload['flush_dns'] else 'not_requested'}
            if self.mutate:
                for row in self.value['adapters']:
                    if row['id'] in {r['id'] for r in payload['adapters']}:row['ipv6_enabled']=False
        elif self.mutate:
            for before in self.record['adapters']:
                row=next(r for r in self.value['adapters'] if r['id']==before['id'])
                row.update(ipv6_enabled=before['ipv6_enabled'],config=copy.deepcopy(before['config']))
            self.record['state']='restored'


class SystemNetworkTests(unittest.TestCase):
    def setUp(self):
        self.store=StateStore(memory=True)
        self.store.save_settings({'usage':'desktop','connection_mode':'tun','usage_country':'US','country':'US',
                                  'timezone':'America/New_York','locale':'en-US','ipv6_mode':'disabled'},confirm_environment=True)
        self.report={'report_id':'fixture','mode':'one-click-desktop','created_at':datetime.now(timezone.utc).isoformat(),
                     'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],
                     'environment':{'fingerprint':fingerprint(self.store.settings())}}
        self.io=NetworkFixture();self.manager=SystemNetwork(self.store,self.io)

    def test_active_only_preview_confirmation_readback_and_restore(self):
        original=self.io.snapshot();plan=self.manager.prepare(self.report,flush_dns=True)
        self.assertEqual(plan['state'],'planned');self.assertFalse(self.io.calls)
        self.assertTrue(any('缓存内容不能撤销' in e for e in plan['effects']))
        for confirmed in (False,1,'true'):self.assertEqual(self.manager.apply(plan['plan_id'],confirmed)['state'],'confirmation_required')
        result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'completed');json.dumps(result)
        self.assertFalse(self.io.value['adapters'][0]['ipv6_enabled'])
        self.assertTrue(self.io.value['adapters'][1]['ipv6_enabled'])
        self.assertEqual(self.io.value['adapters'][0]['config'],original['adapters'][0]['config'])
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required')
        restore=self.manager.prepare_restore()
        self.assertEqual(self.manager.restore(restore['plan_id'],True)['state'],'completed')
        self.assertEqual(self.io.value,original)

    def test_declared_region_fresh_report_and_goal_are_required(self):
        self.assertEqual(self.manager.prepare(None)['state'],'retest_required')
        old=copy.deepcopy(self.report);old['created_at']=(datetime.now(timezone.utc)-timedelta(minutes=4)).isoformat()
        self.assertEqual(self.manager.prepare(old)['state'],'retest_required')
        for actual in ('CN','RU','UA',''):
            self.store.save_settings({'usage_country':actual},confirm_environment=True)
            self.report['environment']['fingerprint']=fingerprint(self.store.settings())
            self.assertEqual(self.manager.prepare(self.report)['state'],'blocked')
        self.assertFalse(self.io.calls)

    def test_observe_target_does_not_silently_disable_ipv6(self):
        self.store.save_settings({'ipv6_mode':'observe'},confirm_environment=True)
        self.report['environment']['fingerprint']=fingerprint(self.store.settings())
        self.assertEqual(self.manager.prepare(self.report)['state'],'guided')
        plan=self.manager.prepare(self.report,adapter_ids=[],flush_dns=True)
        self.assertEqual(plan['state'],'planned')
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'completed')
        self.assertTrue(all(r['ipv6_enabled'] for r in self.io.value['adapters']))
        self.assertEqual(self.manager.prepare_restore()['state'],'guided')

    def test_explicit_inactive_selection_is_bound_to_exact_known_ids(self):
        for invalid in ('all',[A,A],['other'],[True]):
            with self.assertRaises(ValueError):self.manager.prepare(self.report,adapter_ids=invalid)
        plan=self.manager.prepare(self.report,adapter_ids=[B])
        self.manager.apply(plan['plan_id'],True)
        self.assertTrue(self.io.value['adapters'][0]['ipv6_enabled'])
        self.assertFalse(self.io.value['adapters'][1]['ipv6_enabled'])

    def test_changes_after_preview_block_before_any_write(self):
        for field in ('config','active','owner','record','settings'):
            with self.subTest(field=field):
                self.setUp();plan=self.manager.prepare(self.report)
                if field=='config':self.io.value['adapters'][0]['config']['Addresses']=['2001:db8::2']
                elif field=='active':self.io.value['adapters'][0]['active']=False
                elif field=='owner':self.io.value['owner']=502
                elif field=='record':self.io.record['id']='later operation'
                else:self.store.save_settings({'locale':'en-GB'})
                self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required')
                self.assertFalse(self.io.calls)

    def test_command_success_and_restored_marker_without_readback_never_pass(self):
        self.io.mutate=False;plan=self.manager.prepare(self.report)
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'partial')
        self.io.value['adapters'][0]['ipv6_enabled']=False
        restore=self.manager.prepare_restore()
        self.io.record['state']='restored'  # A new state invalidates the reviewed plan.
        self.assertEqual(self.manager.restore(restore['plan_id'],True)['state'],'retest_required')

    def test_undo_does_not_overwrite_later_configuration_and_ignores_unrelated_link_state(self):
        plan=self.manager.prepare(self.report);self.manager.apply(plan['plan_id'],True)
        self.io.value['adapters'][0]['config']['ConfigMethod']='Automatic'
        self.assertEqual(self.manager.prepare_restore()['state'],'blocked')
        self.io.value['adapters'][0]['config']=copy.deepcopy(self.io.record['adapters'][0]['config'])
        restore=self.manager.prepare_restore();self.io.value['adapters'][1]['active']=True
        self.assertEqual(self.manager.restore(restore['plan_id'],True)['state'],'completed')

    def test_pending_dns_only_receipt_can_be_closed_without_repeating_dns_flush(self):
        self.io.record={'state':'partial','id':'a'*32,'owner':501,'adapters':[],'dns_flush':'unverified'}
        self.assertEqual(self.manager.prepare(self.report)['state'],'recovery_required')
        plan=self.manager.prepare_restore()
        self.assertEqual(self.manager.restore(plan['plan_id'],True)['state'],'completed')
        self.assertEqual([c[0] for c in self.io.calls],['restore'])

    def test_other_owner_and_non_boolean_options_are_rejected(self):
        for value in (1,'true'):
            with self.assertRaises(ValueError):self.manager.prepare(self.report,flush_dns=value)
        self.io.record={'state':'committed','id':'a'*32,'owner':502,'adapters':[]}
        self.assertEqual(self.manager.prepare_restore()['state'],'blocked')

    def test_malformed_identity_or_original_data_does_not_authorize_changes(self):
        for mutation in ('duplicate','unknown','owner','bool'):
            value=self.io.snapshot()
            if mutation=='duplicate':value['adapters'].append(copy.deepcopy(value['adapters'][0]))
            elif mutation=='unknown':value['adapters'][0]['config']['unknown']=object()
            elif mutation=='owner':value['owner']=True
            else:value['adapters'][0]['ipv6_enabled']=1
            with self.assertRaises(ValueError):validate_snapshot(value)


if __name__=='__main__':unittest.main()
