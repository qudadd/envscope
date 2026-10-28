import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from envscope.assessment import assessment
from envscope.permissions import permission_help
from envscope.local_facts import config_shape, hosts_overrides
from envscope.baseline import extra_network
from envscope.model import Finding, Status
from envscope.operations import Operations
from envscope.state import StateStore
from envscope.transport import Response, desktop_transport


def finding(key, status='unknown', evidence=()):
    return Finding(key, key, Status(status), 'fixture', 'fixture', list(evidence)).to_dict()


class AssessmentTests(unittest.TestCase):
    def test_unimplemented_and_optional_are_not_permission_requests_or_pass(self):
        report = {'usage': 'desktop', 'findings': [finding('dns.leak'), finding('network.route'), finding('udp.stun'), finding('extra.cli_paths', 'skipped')]}
        result = assessment(report)
        rows = {r['id']: r for r in result['items']}
        self.assertEqual(rows['dns.leak']['state'], 'unsupported')
        self.assertEqual(rows['udp.stun']['state'], 'probe_incomplete')
        self.assertEqual(rows['extra.cli_paths']['state'], 'not_applicable')
        self.assertTrue(all(r['action'] is None for r in result['items']))
        self.assertEqual(result['verdict'], 'incomplete')

    def test_real_permission_denial_is_distinct_from_io_failure(self):
        report = {'report_id': 'fixture', 'findings': [finding('extra.hosts', evidence=[{'error': 'permission_denied'}]), finding('extra.config', evidence=[{'error': 'unreadable'}])]}
        rows = {r['id']: r for r in assessment(report)['items']}
        self.assertEqual(rows['extra.hosts']['state'], 'permission')
        self.assertNotEqual(rows['extra.config']['state'], 'permission')
        runner = Mock()
        params = {'report_id': 'fixture', 'finding_id': 'extra.hosts'}
        self.assertEqual(permission_help(report, params, Path('/home'), Path('/profile'), runner=runner)['state'], 'confirmation_required')
        runner.assert_not_called()
        result = permission_help(report, params, Path('/home'), Path('/profile'), True, runner, 'Windows')
        self.assertEqual(result['state'], 'opened')
        self.assertFalse(result['permission_granted'])
        with self.assertRaises(ValueError):
            permission_help(report, {**params, 'finding_id': 'extra.config'}, Path('/home'), Path('/profile'))

    def test_denied_file_reads_preserve_reason(self):
        path = Mock()
        path.stat.side_effect = PermissionError()
        self.assertEqual(config_shape(path)['error'], 'permission_denied')
        self.assertEqual(hosts_overrides(path)['error'], 'permission_denied')

    def test_basic_qualified_scope_does_not_claim_privacy_pass(self):
        ids = ('extra.dns_resolution', 'extra.tls', 'baseline.reachability', 'extra.config', 'extra.storage', 'extra.desktop', 'extra.profile', 'extra.account', 'http.egress')
        report = {'usage': 'desktop', 'policy': {'required_checks': ['dns.leak']}, 'findings': [finding(k, 'pass') for k in ids] + [finding('dns.leak')]}
        result = assessment(report)
        self.assertEqual(result['verdict'], 'qualified_in_scope')
        self.assertEqual(report['findings'][-1]['status'], 'unknown')
        report['findings'][0]['status'] = 'unknown'
        self.assertEqual(assessment(report)['verdict'], 'incomplete')
        report['findings'][0]['status'] = 'fail'
        self.assertEqual(assessment(report)['verdict'], 'needs_fix')

    def test_cli_disabled_tls_is_a_problem_not_only_review(self):
        result = assessment({'usage': 'cli', 'findings': [finding('extra.cli_env', 'warn', [{'tls_verification_disabled': True}])]})
        self.assertEqual(result['verdict'], 'needs_fix')

    def test_models_probe_uses_get_both_during_audit_and_proxy_test(self):
        transport = Mock()
        transport.proxy = 'http://127.0.0.1:7897'
        transport.get.return_value = Response(status=401, tls_verified=True)
        extra_network(transport)
        transport.get.assert_any_call('https://api.anthropic.com/v1/models', headers_only=False)
        with tempfile.TemporaryDirectory() as home, patch('envscope.operations.CurlTransport', return_value=transport):
            operations = Operations(StateStore(memory=True), home=home, discoverer=lambda: [])
            result = operations.run('proxy-diagnose', {'proxy': transport.proxy})
            self.assertTrue(operations.solutions._proxy_verified(result))
            transport.get.assert_any_call('https://api.anthropic.com/v1/models', headers_only=False)

    def test_system_http_proxy_used_without_overriding_environment(self):
        with patch.dict('os.environ', {}, clear=True), patch('envscope.local_facts.read_system_proxy', return_value={'enabled': True, 'endpoints': ['http://127.0.0.1:7897']}):
            self.assertEqual(desktop_transport().proxy, 'http://127.0.0.1:7897')
        with patch.dict('os.environ', {'HTTPS_PROXY': 'http://127.0.0.1:9888'}, clear=True), patch('envscope.local_facts.read_system_proxy') as read:
            self.assertIsNone(desktop_transport().proxy)
            read.assert_not_called()
