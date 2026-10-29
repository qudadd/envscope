"""Persistent controls must change real probe selection, never fabricate a pass."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.check_preferences import validate, catalog, selection, GROUPS
from envscope.ecosystem import ENDPOINTS, finding, observe
from envscope.model import make_report, Finding, Status
from envscope.policy import Policy
from envscope.probes import audit
from envscope.state import StateStore
from envscope.transport import Response
from scripts.environment_fixtures import target, fixture


class CheckPreferenceTests(unittest.TestCase):
    def test_strict_whitelist_duplicate_and_boolean_validation(self):
        for config in ({'disabled': ['unknown']}, {'disabled': ['dns', 'dns']}, {'disabled': 'dns'},
                       {'disabled': [None]}, {'allow_optional_failures': 1}, {'logging': 'false'},
                       {'extra': True}):
            with self.subTest(config=config), self.assertRaises(ValueError): validate(config)
        self.assertEqual(len(GROUPS), 6)

    def test_persistence_and_caller_mutation_do_not_change_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory)/'state')
            config = {'disabled': ['webrtc', 'ecosystem'], 'logging': False}
            store.save_settings({'check_config': config})
            config['disabled'].clear()
            actual = StateStore(store.root).settings()['check_config']
            self.assertEqual(actual['disabled'], ['ecosystem', 'webrtc'])
            self.assertFalse(actual['logging'])

    def test_optional_groups_never_disable_required_target_or_dependencies(self):
        settings = target(usage='desktop', mode='tun', protection='guarded', ipv6_mode='disabled', language='en-US',
                          check_config={'disabled': [g[0] for g in GROUPS]})
        enabled = selection(settings)
        for key in ('target.region', 'http.egress', 'target.dns', 'target.tls', 'target.service',
                    'udp.stun', 'baseline.language', 'baseline.tun', 'baseline.guard', 'baseline.rules'):
            self.assertIn(key, enabled)
        self.assertNotIn('extra.ecosystem', enabled)
        self.assertNotIn('baseline.asn', enabled)
        self.assertIn('udp.stun', next(g for g in catalog(settings)['groups'] if g['id']=='webrtc')['required'])

    def test_explicit_one_run_selection_can_measure_a_disabled_optional_item(self):
        settings = target(check_config={'disabled': ['ecosystem']})
        self.assertNotIn('extra.ecosystem', selection(settings))
        self.assertEqual(selection(settings, ['extra.ecosystem']), ['extra.ecosystem'])

    def test_logging_consent_does_not_invalidate_guard_but_probe_policy_does(self):
        from envscope.maintenance import fingerprint
        from envscope.operations import Operations
        with tempfile.TemporaryDirectory() as directory:
            store=StateStore(Path(directory)/'state')
            ops=Operations(store,Path(directory),discoverer=lambda:[])
            before=fingerprint(store.settings())
            result=ops.run('check-config-save',{'logging':False})
            self.assertFalse(result['requires_retest'])
            self.assertEqual(fingerprint(store.settings()),before)
            result=ops.run('check-config-save',{'logging':False,'disabled':['ecosystem']})
            self.assertTrue(result['requires_retest'])
            self.assertNotEqual(fingerprint(store.settings()),before)
            changed=fingerprint(store.settings())
            result=ops.run('check-config-save',{'logging':True})
            self.assertFalse(result['requires_retest'])
            self.assertEqual(store.settings()['check_config']['disabled'],['ecosystem'])
            self.assertEqual(fingerprint(store.settings()),changed)

    def test_disabled_probes_make_no_network_requests_and_results_stay_skipped(self):
        settings = target(check_config={'disabled': ['ecosystem', 'webrtc']})
        inventory = {'network': {}, 'locale': 'zh-CN'}
        transport = Mock(path='fixture-only', proxy=None)
        transport.get.return_value = Response(error='fixture_offline')
        with patch('envscope.probes.collect', return_value=inventory), \
             patch('envscope.probes.bounded_facts', return_value={}), \
             patch('envscope.probes.local_snapshot', return_value={}), \
             patch('envscope.environment_info.device_information', return_value={}), \
             patch('envscope.baseline.guard_state', return_value={}), \
             patch('envscope.baseline.runtime_rules', return_value={'status':'unknown', 'reason':'fixture'}), \
             patch('envscope.ecosystem.observe') as ecosystem, patch('envscope.probes.stun_observations') as stun:
            findings = audit(Policy(), transport, online=True, stun=True, ipv6=True, baseline_config=settings)
        ecosystem.assert_not_called(); stun.assert_not_called()
        self.assertFalse(any(call.args[0] in ENDPOINTS for call in transport.get.call_args_list))
        rows = {f.id: f for f in findings}
        for key in ('extra.ecosystem', 'udp.stun', 'browser.webrtc', 'baseline.webrtc'):
            self.assertEqual(rows[key].status, Status.SKIPPED)
        report = make_report(findings, Policy(), preferences=settings)
        self.assertNotEqual(report['decision']['verdict'], 'clear_in_scope')

    def test_noncritical_failure_option_preserves_failure_and_cannot_relax_mandatory_language(self):
        with tempfile.TemporaryDirectory() as home:
            for allow in (False, True):
                settings = target(check_config={'allow_optional_failures':allow})
                rows = fixture(home, settings)
                next(f for f in rows if f.id=='extra.ecosystem').status = Status.FAIL
                report = make_report(rows, Policy(), preferences=settings)
                self.assertEqual(next(f['status'] for f in report['findings'] if f['id']=='extra.ecosystem'), 'fail')
                self.assertEqual(report['assessment']['verdict']=='qualified_in_scope', allow)
                self.assertEqual(report['check_config']['nonblocking_failures'], ['extra.ecosystem'] if allow else [])
            settings = target(usage='desktop', language='en-US', check_config={'allow_optional_failures':True})
            rows = fixture(home, settings)
            next(f for f in rows if f.id=='baseline.language').status = Status.FAIL
            report = make_report(rows, Policy(), preferences=settings)
            self.assertNotEqual(report['assessment']['verdict'], 'qualified_in_scope')
            self.assertNotIn('baseline.language', report['check_config']['nonblocking_failures'])

    def test_address_policy_and_missing_guarded_udp_are_never_softened(self):
        settings = target(mode='tun', protection='guarded', ipv6_mode='disabled', check_config={'allow_optional_failures':True, 'disabled':['webrtc']})
        for status in (Status.FAIL, Status.UNKNOWN, Status.SKIPPED):
            report = make_report([Finding('udp.stun','UDP',status,'fixture','fixture')], Policy(), preferences=settings)
            self.assertEqual(report['check_config']['nonblocking_failures'], [])
            self.assertNotEqual(report['assessment']['verdict'], 'qualified_in_scope')
            if status == Status.FAIL: self.assertEqual(report['decision']['verdict'], 'blocked')

    def test_partial_ecosystem_warning_can_be_nonblocking_but_certificate_failure_cannot(self):
        with tempfile.TemporaryDirectory() as home:
            for allow in (False,True):
                settings=target(check_config={'allow_optional_failures':allow})
                rows=fixture(home,settings)
                item=next(f for f in rows if f.id=='extra.ecosystem')
                item.status=Status.WARN;item.evidence=[{'endpoint':ENDPOINTS[0],'error':'deadline_exceeded'}]
                report=make_report(rows,Policy(),preferences=settings)
                self.assertEqual(report['assessment']['verdict']=='qualified_in_scope',allow)
                item.status=Status.FAIL;item.evidence=[{'endpoint':ENDPOINTS[0],'tls_verified':False}]
                report=make_report(rows,Policy(),preferences=settings)
                self.assertNotEqual(report['assessment']['verdict'],'qualified_in_scope')
                self.assertEqual(report['check_config']['nonblocking_failures'],[])

    def test_background_uses_saved_selection_and_logging_optout(self):
        from envscope.maintenance import Maintenance
        from test_maintenance import FakeScheduler
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve(); store = StateStore(home/'state')
            settings = target(check_config={'disabled':['ecosystem', 'webrtc'], 'logging':False})
            store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'}, confirm_environment=True)
            auditor = Mock(return_value=fixture(home, settings))
            manager = Maintenance(store, home=home, scheduler=FakeScheduler(), auditor=auditor)
            manager._write('config', {'version':1,'enabled':True,'interval':15,'auto_restore':False,
                                      'settings_hash':'fixture', 'schedule':{'body':'fixture'}})
            result = manager.run_once()
            self.assertEqual(result['state'], 'completed')
            self.assertEqual(auditor.call_args.kwargs['selected_checks'], selection(settings))
            self.assertEqual(next(f['status'] for f in result['report']['findings'] if f['id']=='extra.ecosystem'), 'skipped')
            self.assertFalse((store.root/'diagnostics').exists())

    def test_preferences_changing_mid_audit_cannot_label_old_evidence_as_current(self):
        from envscope.operations import Operations
        from envscope.service import collect_report
        store=StateStore(memory=True)
        with tempfile.TemporaryDirectory() as home:
            ops=Operations(store,Path(home),discoverer=lambda:[])
            def auditor(*args,**kwargs):
                store.save_settings({'check_config':{'disabled':['ecosystem']}})
                return []
            server=SimpleNamespace(store=store,operations=ops,auditor=auditor,last_raw_report={'old':'must invalidate'})
            with self.assertRaises(ValueError):collect_report(server,{'http':[]})
            self.assertIsNone(server.last_raw_report)
            self.assertEqual(ops.diagnostics.entries()[-1]['state'],'failed')

    def test_ecosystem_requires_all_unique_verified_responses_and_describes_http_limits(self):
        rows = [{'endpoint':url, 'http_status':403,'tls_verified':True,'error':None} for url in ENDPOINTS]
        value = finding(rows)
        self.assertEqual(value.status, Status.PASS)
        self.assertIn('403/404', str(value.limitations))
        for bad in ([], rows[:-1], [rows[0]]*len(rows), [{**r,'tls_verified':False} for r in rows]):
            self.assertNotEqual(finding(bad).status, Status.PASS)
        transport = Mock(); transport.get.return_value = Response(status=404,tls_verified=True)
        self.assertEqual(len(observe(transport)),len(ENDPOINTS))
        self.assertTrue(all(c.kwargs=={'headers_only':True} for c in transport.get.call_args_list))
