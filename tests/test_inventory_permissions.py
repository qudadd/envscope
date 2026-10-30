"""Permission evidence fixtures; no real commands or system mutations."""
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from envscope.assessment import assessment, denied
from envscope.baseline import collect_baseline, proxy_runtime, tunnel
from envscope.inventory import command_text, macos_network
from envscope.network_facts import lookup_routes
from envscope.policy import Policy
from envscope.probes import audit
from envscope.model import Finding, Status


def mac_reader(failure):
    def read(command, **kwargs):
        if command == ['/usr/sbin/scutil', '--dns']:
            raise failure
        if command[0] == '/sbin/ifconfig':
            return 'en0: flags=8863<UP,BROADCAST,RUNNING>\n inet 192.0.2.10\n'
        if command[0] == '/sbin/route':
            return 'gateway: 192.0.2.1\ninterface: en0\n'
        return ''
    return read


class InventoryPermissionTests(unittest.TestCase):
    def test_partial_values_cannot_hide_denied_baseline_reads(self):
        inventory = {'locale': 'en-US', 'network': {'timezone_id': 'UTC', 'dns': ['192.0.2.2'],
                     'ipv6_bindings': [{'Enabled': False}], 'errors': {
                         name: {'error': 'permission_denied'} for name in ('timezone', 'locale', 'dns', 'ipv6_bindings')}}}
        unknown = Finding('fixture', 'fixture', Status.UNKNOWN, 'fixture', 'fixture')
        rows = collect_baseline(inventory, [], [], unknown, unknown, {'timezone': 'UTC', 'locale': 'en-US'}, Mock(), enabled=set())
        for key in ('timezone', 'locale', 'dns', 'ipv6'):
            with self.subTest(component=key):
                row = next(r for r in rows if r.id == 'baseline.' + key)
                self.assertEqual(row.status, Status.UNKNOWN)
                self.assertTrue(denied(row.evidence))

    def test_truncated_route_results_cannot_omit_the_failed_address(self):
        completed = subprocess.CompletedProcess(['fixture'], 0, stdout='[]', stderr='')
        rows = lookup_routes(['192.0.2.1'], 'Windows', Mock(return_value=completed))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['error'], 'invalid_response')

    def test_denied_dns_is_explained_as_permission_in_the_report(self):
        with patch('envscope.inventory.command_text', side_effect=mac_reader(PermissionError())):
            network = macos_network()
        with patch('envscope.probes.collect', return_value={'platform': 'Darwin', 'network': network}):
            rows = audit(Policy(), Mock(), selected_checks=['system.inventory'])
        report = {'findings': [row.to_dict() for row in rows]}
        item = next(row for row in assessment(report)['items'] if row['id'] == 'system.inventory')
        self.assertEqual(item['state'], 'permission')
        self.assertEqual(item['action'], 'permission-help')
        self.assertEqual(network['errors']['dns']['error'], 'permission_denied')

    def test_failed_subcollection_never_becomes_a_completed_inventory(self):
        for failure in (PermissionError(), subprocess.TimeoutExpired('fixture', 3), FileNotFoundError(), OSError()):
            with self.subTest(failure=type(failure).__name__):
                with patch('envscope.inventory.command_text', side_effect=mac_reader(failure)):
                    network = macos_network()
                with patch('envscope.probes.collect', return_value={'platform': 'Darwin', 'network': network}):
                    row = next(f for f in audit(Policy(), Mock(), selected_checks=['system.inventory']) if f.id == 'system.inventory')
                self.assertEqual(row.status.value, 'unknown')
                self.assertNotIn('已采集', row.summary)

    def test_timeout_and_missing_tool_are_not_reported_as_permission(self):
        for failure, expected in ((subprocess.TimeoutExpired('fixture', 3), 'timeout'), (FileNotFoundError(), 'tool_missing')):
            with self.subTest(expected=expected):
                with patch('envscope.inventory.command_text', side_effect=mac_reader(failure)):
                    network = macos_network()
                self.assertEqual(network.get('errors', {}).get('dns', {}).get('error'), expected)
                self.assertFalse(denied(network))

    def test_process_and_tunnel_denials_reach_the_affected_check(self):
        for key, make in (('known_clients', lambda value: proxy_runtime(value, {})), ('adapters', tunnel)):
            with self.subTest(component=key):
                value = {'network': {key: [], 'errors': {key: {'error': 'permission_denied', 'operation': key}}}}
                finding = make(value).to_dict()
                row = assessment({'findings': [finding]})['items'][0]
                self.assertEqual(row['state'], 'permission')

    def test_legacy_partial_inventory_errors_are_not_ignored(self):
        for key in ('dns_error', 'default_route_error'):
            with self.subTest(component=key):
                inventory = {'platform': 'Darwin', 'network': {'adapters': [], key: 'unavailable'}}
                with patch('envscope.probes.collect', return_value=inventory):
                    row = next(f for f in audit(Policy(), Mock(), selected_checks=['system.inventory']) if f.id == 'system.inventory')
                self.assertEqual(row.status.value, 'unknown')

    def test_denied_command_has_a_safe_machine_readable_error(self):
        completed = subprocess.CompletedProcess(['fixture'], 1, stdout='', stderr='scutil: Permission denied PRIVATE_CREDENTIAL')
        with patch('envscope.inventory.subprocess.run', return_value=completed):
            with self.assertRaises(OSError) as raised:
                command_text(['/usr/sbin/scutil', '--dns'])
        self.assertEqual(getattr(raised.exception, 'code', None), 'permission_denied')
        self.assertNotIn('PRIVATE_CREDENTIAL', str(raised.exception))

    def test_route_read_denial_remains_actionable_on_both_platforms(self):
        for system in ('Windows', 'Darwin'):
            with self.subTest(system=system):
                result = lookup_routes(['192.0.2.1'], system, Mock(side_effect=PermissionError()))
                self.assertEqual(result[0]['error'], 'permission_denied')
                self.assertTrue(denied(result))

    def test_route_timeout_is_distinct_from_denial(self):
        for system in ('Windows', 'Darwin'):
            with self.subTest(system=system):
                result = lookup_routes(['192.0.2.1'], system, Mock(side_effect=subprocess.TimeoutExpired('fixture', 3)))
                self.assertEqual(result[0]['error'], 'timeout')
                self.assertFalse(denied(result))

    def test_denied_route_command_response_does_not_expose_stderr(self):
        completed = subprocess.CompletedProcess(['fixture'], 1, stdout='', stderr='route: Operation not permitted PRIVATE_CREDENTIAL')
        result = lookup_routes(['192.0.2.1'], 'Darwin', Mock(return_value=completed))
        self.assertEqual(result[0]['error'], 'permission_denied')
        self.assertNotIn('PRIVATE_CREDENTIAL', json.dumps(result))
