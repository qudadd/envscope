"""Permission steps use fixture launchers only; no OS dialogs are opened."""
from pathlib import Path
import unittest
from unittest.mock import Mock

from envscope.permissions import permission_help


class PermissionFlowTests(unittest.TestCase):
    def report(self, key, evidence=None):
        return {'report_id': 'current', 'usage': 'cli', 'findings': [
            {'id': key, 'evidence': evidence or [{'error': 'permission_denied'}]}]}

    def call(self, key, system='Windows', evidence=None, confirmed=False, runner=None):
        return permission_help(self.report(key, evidence), {'report_id': 'current', 'finding_id': key},
                               Path('/fixture/home'), Path('/fixture/Claude'), confirmed, runner or Mock(), system)

    def test_inventory_denial_has_scoped_entry_on_both_platforms(self):
        evidence = [{'network': {'errors': {'dns': {'error': 'permission_denied'}}}}]
        for system in ('Windows', 'Darwin'):
            with self.subTest(system=system):
                value = self.call('system.inventory', system, evidence)
                self.assertEqual(value['state'], 'confirmation_required')
                self.assertEqual(value['capabilities'][0]['id'], 'network-read')
                self.assertEqual(value['scope'], 'read')
                self.assertIn('baseline.dns', value['affected_checks'])
                self.assertFalse(value['permission_granted'])

    def test_native_network_denial_never_opens_file_privacy(self):
        runner = Mock()
        value = self.call('target.tun_route', 'Darwin', confirmed=True, runner=runner)
        self.assertEqual(value['state'], 'opened')
        command = runner.call_args.args[0]
        self.assertTrue(any('Network' in part for part in command))
        self.assertFalse(any('FilesAndFolders' in part for part in command))

    def test_file_and_service_requests_remain_read_only(self):
        for key in ('extra.hosts', 'extra.config', 'target.config', 'extra.cli_env', 'extra.profile', 'target.wireguard'):
            with self.subTest(key=key):
                value = self.call(key)
                self.assertEqual(value['state'], 'confirmation_required')
                self.assertEqual(value['scope'], 'read')
                self.assertTrue(value['capabilities'])
                self.assertFalse(value['permission_granted'])

    def test_tool_launch_failure_is_actionable_not_a_grant(self):
        value = self.call('extra.config', confirmed=True, runner=Mock(side_effect=FileNotFoundError()))
        self.assertEqual(value['state'], 'unavailable')
        self.assertEqual(value['error'], 'tool_missing')
        self.assertFalse(value['permission_granted'])
        self.assertTrue(value['manual_steps'])

    def test_policy_denial_is_manual_without_retrying_elevation(self):
        runner = Mock()
        value = self.call('system.inventory', evidence=[{'error': 'policy_denied'}], confirmed=True, runner=runner)
        self.assertEqual(value['state'], 'manual')
        self.assertEqual(value['error'], 'policy_denied')
        runner.assert_not_called()

    def test_stale_and_unmeasured_requests_do_not_open_settings(self):
        runner = Mock()
        report = self.report('extra.config')
        value = permission_help(report, {'report_id': 'old', 'finding_id': 'extra.config'}, Path('.'), Path('.'), True, runner, 'Windows')
        self.assertEqual(value['state'], 'retest_required')
        for evidence in ([{'error': 'timeout'}], [{'error': 'invalid_response'}]):
            with self.assertRaises(ValueError):
                self.call('extra.config', evidence=evidence, confirmed=True, runner=runner)
        runner.assert_not_called()
