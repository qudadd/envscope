"""One-stop and selective operations use the injected network executor only."""
import copy
from datetime import datetime,timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from envscope.operations import Operations
from envscope.state import StateStore
from envscope.system_network import SystemNetwork
from envscope.target_environment import fingerprint
from tests.test_system_network import NetworkFixture,A,B


class NetworkIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name).resolve();self.store=StateStore(self.home/'state')
        self.store.save_settings({'usage':'desktop','connection_mode':'tun','usage_country':'US','country':'US',
                                 'ipv6_mode':'disabled'},confirm_environment=True)
        self.io=NetworkFixture();self.network=SystemNetwork(self.store,self.io)
        self.legacy=Mock();self.legacy.capabilities.return_value={'actions':[]}
        self.ops=Operations(self.store,self.home,network=self.network,legacy=self.legacy,discoverer=lambda:[],
                            environment_reader=lambda:{'platform':'Windows','locale':'en-US'})
        self.report={'report_id':'fixture-network','mode':'one-click-desktop','usage':'desktop',
                     'created_at':datetime.now(timezone.utc).isoformat(),
                     'environment':{'fingerprint':fingerprint(self.store.settings()),'targets':self.store.settings(),
                                    'required':['target.region','target.ipv6','target.dns']},
                     'diagnosis':{'problems':[]},'findings':[]}
        for key,status in (('target.region','pass'),('target.ipv6','fail'),('target.dns','fail')):
            self.report['findings'].append({'id':key,'status':status,'title':key,'scope':'fixture',
                                           'summary':'Fixture measured result','suggestion':'Recheck after reviewed repair'})
            if status=='fail':self.report['diagnosis']['problems'].append({'id':key,'title':key,'repair':None,'steps':['Recheck']})

    def test_one_stop_repairs_only_declared_active_interfaces_and_flushes_once(self):
        plan=self.ops.run('solution-plan',{'report_id':self.report['report_id']},report=self.report)
        self.assertEqual(plan['state'],'planned');self.assertFalse(self.io.calls)
        for confirmation in (False,1,'true'):
            self.assertEqual(self.ops.run('solution-apply',{'plan_id':plan['plan_id']},confirmation,self.report)['state'],'confirmation_required')
        result=self.ops.run('solution-apply',{'plan_id':plan['plan_id']},True,self.report)
        self.assertEqual(result['state'],'executed');self.assertTrue(result['needs_retest'])
        self.assertEqual([r['step'] for r in result['steps']],['system-network'])
        self.assertFalse(self.io.value['adapters'][0]['ipv6_enabled'])
        self.assertTrue(self.io.value['adapters'][1]['ipv6_enabled'])
        self.assertTrue(self.io.calls[0][1]['flush_dns']);self.legacy.run.assert_not_called()

    def test_selective_dns_cannot_authorize_ipv6_changes_and_vice_versa(self):
        for key,expect_ids,expect_dns in (('target.dns',[],True),('target.ipv6',[A],False)):
            with self.subTest(key=key):
                self.setUp()
                plan=self.ops.run('inspection-plan',{'report_id':self.report['report_id'],'check_ids':[key]},report=self.report)
                self.assertEqual(plan['state'],'planned');self.assertFalse(self.io.calls)
                result=self.ops.run('inspection-apply',{'plan_id':plan['plan_id']},True,self.report)
                self.assertEqual(result['state'],'executed')
                payload=self.io.calls[0][1]
                self.assertEqual([r['id'] for r in payload['adapters']],expect_ids)
                self.assertEqual(payload['flush_dns'],expect_dns)

    def test_network_panel_options_preserve_private_binary_configuration(self):
        import json
        options=self.ops.run('system-network-options',{})
        self.assertEqual(options['state'],'completed');json.dumps(options)
        self.assertNotIn('config',options['adapters'][0]);self.assertFalse(self.io.calls)
        original=self.io.snapshot()
        plan=self.ops.run('system-network-plan',{'report_id':self.report['report_id'],'adapter_ids':[B]},report=self.report)
        self.assertEqual(self.ops.run('system-network-apply',{'plan_id':plan['plan_id']},True)['state'],'completed')
        restore=self.ops.run('system-network-restore-plan',{})
        self.assertEqual(self.ops.run('system-network-restore',{'plan_id':restore['plan_id']},True)['state'],'completed')
        self.assertEqual(self.io.snapshot(),original)

    def test_failed_network_executor_stops_without_legacy_fallback(self):
        plan=self.ops.run('solution-plan',{'report_id':self.report['report_id']},report=self.report)
        self.io.execute=Mock(side_effect=ValueError('Fixture authorization cancelled'))
        result=self.ops.run('solution-apply',{'plan_id':plan['plan_id']},True,self.report)
        self.assertEqual(result['state'],'partial');self.assertTrue(result['needs_retest'])
        self.assertTrue(all(r['ipv6_enabled'] for r in self.io.value['adapters']))
        self.legacy.run.assert_not_called()

    def test_unselected_and_unknown_results_never_authorize_network_writes(self):
        plan=self.ops.run('inspection-plan',{'report_id':self.report['report_id'],'check_ids':['extra.config']},report=self.report)
        self.assertNotEqual(plan['state'],'planned');self.assertFalse(self.io.calls)
        for row in self.report['findings']:
            if row['id']!='target.region':row['status']='unknown'
        self.report['diagnosis']['problems']=[]
        plan=self.ops.run('solution-plan',{'report_id':self.report['report_id']},report=self.report)
        self.assertEqual(plan['state'],'guided');self.assertFalse(self.io.calls)

    def test_fixed_action_parameters_and_current_report_are_required(self):
        for action,params in (('system-network-options',{'file':'somewhere'}),
                              ('system-network-apply',{'plan_id':'x','adapter_ids':[A]}),
                              ('system-network-any-command',{})):
            with self.assertRaises(ValueError):self.ops.run(action,params)
        result=self.ops.run('system-network-plan',{'report_id':'old','adapter_ids':[A]},report=self.report)
        self.assertEqual(result['state'],'retest_required');self.assertFalse(self.io.calls)
