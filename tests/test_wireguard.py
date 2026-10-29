"""Fixtures and read-only command parsing; never install/start a real VPN."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from envscope.wireguard import (WireGuardReader, WindowsServices, command_identity,
                               select_service, finding, valid_service, binary_digest, PREFIX)
from envscope.process_guard import ProcessGuard, health, validate_baseline
from envscope.state import StateStore, validate_settings
from envscope.accounts import AccountError
from envscope.target_environment import build_findings, plan, fingerprint, FIELDS
from envscope.model import Finding, Status, make_report
from envscope.operations import Operations
from envscope.permissions import permission_help
from envscope.report import redact
from scripts.environment_fixtures import fixture, fixture_policy, target
from tests.test_process_guard import GuardIOFixture, GuardSchedulerFixture

SERVICE = PREFIX + 'EnvScope Fixture US'
BINARY = r'C:\Program Files\WireGuard\wireguard.exe'
SHA = 'e' * 64


class ServiceFixture:
    def __init__(self):
        self.config = {'type': 0x10, 'status_type': 0x10, 'start': 3, 'account': 'LocalSystem',
                       'command': 'FIXTURE_NOT_EXECUTABLE', 'state': 4, 'pid': 1729}
        self.process_value = {'path': BINARY, 'created': 123456789, 'exited': False}
        self.args = [BINARY, '/tunnelservice', r'C:\private\EnvScope Fixture US.conf.dpapi']
        self.reads, self.processes = 0, 0
        self.changed_config, self.changed_process, self.error = False, False, None

    def read(self, name):
        self.reads += 1
        if self.error: raise self.error
        value = deepcopy(self.config)
        if self.changed_config and self.reads > 1: value['pid'] += 1
        return value

    def argv(self, command): return list(self.args)

    def process(self, pid):
        self.processes += 1
        value = deepcopy(self.process_value)
        if self.changed_process and self.processes > 1: value['created'] += 1
        return value


def observed():
    api = ServiceFixture()
    return WireGuardReader('Windows', lambda: [SERVICE], api, [BINARY], lambda *args: SHA).collect()


def wireguard_findings(home, settings, observation=None, *, route='EnvScope Fixture US'):
    rows = fixture(home, settings)
    inventory = next(f for f in rows if f.id == 'system.inventory').evidence[0]
    inventory['network']['wireguard'] = deepcopy(observation if observation is not None else observed())
    inventory['network']['adapters'] = [
        {'Name': 'EnvScope Fixture US', 'InterfaceDescription': 'WireGuard Tunnel', 'Status': 'Up', 'ifIndex': 8},
        {'Name': 'Other VPN', 'InterfaceDescription': 'Wintun', 'Status': 'Up', 'ifIndex': 19}]
    next(f for f in rows if f.id == 'extra.target_route').evidence = [
        {'destination': '8.8.8.8', 'interface': route, 'interface_index': 8 if route == 'EnvScope Fixture US' else 19}]
    # fixture audit already derived target rows. Rebuild from these updated raw
    # observations, exactly as production make_report does, not desired values.
    rows = [f for f in rows if not f.id.startswith('target.')]
    return rows


def wireguard_report(home, settings, observation=None, *, route='EnvScope Fixture US'):
    return make_report(wireguard_findings(home, settings, observation, route=route), fixture_policy(settings), 'one-click-desktop', settings)


class WireGuardTests(unittest.TestCase):
    def reader(self, api=None, **kwargs):
        return WireGuardReader('Windows', lambda: [SERVICE], api or ServiceFixture(), [BINARY],
                               kwargs.get('digest', lambda *args: SHA))

    def test_scm_process_and_program_all_required_without_key_material(self):
        api = ServiceFixture(); value = self.reader(api).collect()
        self.assertEqual(select_service(value)[0], 'healthy', value)
        self.assertEqual((api.reads, api.processes), (2, 2))
        self.assertEqual(finding(value).status, Status.PASS)
        serialized = json.dumps(value)
        self.assertNotIn('private', serialized); self.assertNotIn('.conf', serialized)
        self.assertNotIn('command', serialized); self.assertNotIn('LocalSystem', serialized)

    def test_named_process_wrong_account_shared_service_and_replaced_identity_rejected(self):
        cases = [('config', 'type', 0x20), ('config', 'status_type', 0x20), ('config', 'account', 'other-user'),
                 ('config', 'pid', 0), ('config', 'pid', True), ('process_value', 'path', r'C:\temp\wireguard.exe'),
                 ('process_value', 'exited', True), ('process_value', 'created', None)]
        for section, key, bad in cases:
            with self.subTest(key=key, bad=bad):
                api = ServiceFixture(); getattr(api, section)[key] = bad
                self.assertNotEqual(select_service(self.reader(api).collect())[0], 'healthy')
        for name in ('changed_config', 'changed_process'):
            api = ServiceFixture(); setattr(api, name, True)
            self.assertNotEqual(select_service(self.reader(api).collect())[0], 'healthy')
        digests = iter([SHA, 'f' * 64])
        self.assertNotEqual(select_service(self.reader(digest=lambda *args: next(digests)).collect())[0], 'healthy')

    def test_offline_missing_ambiguous_and_permission_states_are_actionable(self):
        api = ServiceFixture(); api.config['state'] = 1; api.config['pid'] = 0
        value = self.reader(api).collect()
        self.assertEqual(select_service(value)[0], 'offline'); self.assertEqual(finding(value).status, Status.FAIL)
        self.assertEqual(api.processes, 0)
        empty = {'platform': 'Windows', 'complete': True, 'services': []}
        self.assertEqual(finding(empty).status, Status.FAIL)
        api = ServiceFixture(); api.error = PermissionError('FIXTURE_ONLY')
        self.assertEqual(select_service(self.reader(api).collect())[0], 'permission')
        self.assertEqual(finding(self.reader(api).collect()).status, Status.UNKNOWN)
        value = observed(); second = deepcopy(value['services'][0]); second['service'] = PREFIX + 'other'
        value['services'].append(second)
        self.assertEqual(select_service(value)[0], 'ambiguous')
        self.assertEqual(select_service(value, SERVICE)[0], 'healthy')
        value['complete'] = False
        self.assertEqual(select_service(value, SERVICE)[0], 'unknown')
        self.assertEqual(select_service({'platform': 'Darwin'})[0], 'unsupported')
        self.assertEqual(select_service(None)[0], 'unknown')

    def test_unrecognized_commands_remote_paths_and_mismatched_config_names_rejected(self):
        good = [BINARY, '/tunnelservice', r'D:\VPN\EnvScope Fixture US.conf']
        self.assertEqual(command_identity(good, SERVICE, [BINARY]), BINARY)
        commands = [[BINARY], good + ['extra'], [BINARY, '/installtunnelservice', good[2]],
                    [r'C:\Users\somebody\wireguard.exe', *good[1:]],
                    [BINARY, good[1], r'\\server\VPN\EnvScope Fixture US.conf'],
                    [BINARY, good[1], r'C:\VPN\other.conf'],
                    [BINARY, good[1], r'C:\VPN\..\EnvScope Fixture US.conf'],
                    [BINARY, good[1], r'C:\VPN\EnvScope Fixture US.conf:alternate']]
        for args in commands:
            with self.subTest(args=args), self.assertRaises(ValueError): command_identity(args, SERVICE, [BINARY])
        for service in ('', 'WireGuardManager', PREFIX, PREFIX + 'bad/name', PREFIX + '\n'):
            self.assertFalse(valid_service(service))
        self.assertTrue(valid_service(PREFIX + '中文隧道'))

    def test_hash_checks_owned_file_and_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve()/'owned-fixture.bin'; path.write_bytes(b'ENVSCOPE_FIXTURE_ONLY')
            self.assertEqual(binary_digest(path, time.monotonic()+3), hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(TimeoutError): binary_digest(path, time.monotonic()-1)

    @unittest.skipUnless(os.name == 'nt', 'Windows read-only command parser')
    def test_actual_windows_parser_no_shell_or_service_actions(self):
        api = WindowsServices()
        args = api.argv('"'+BINARY+'" /tunnelservice "C:\\private\\EnvScope Fixture US.conf.dpapi"')
        self.assertEqual(command_identity(args, SERVICE, [BINARY]), BINARY)
        with self.assertRaises(ValueError):
            command_identity(api.argv(BINARY + ' /tunnelservice "C:\\private\\EnvScope Fixture US.conf"'), SERVICE, [BINARY])

    def test_unknown_or_malformed_inventory_never_passes(self):
        cases = [lambda: (_ for _ in ()).throw(PermissionError()), lambda: [SERVICE] * 2,
                 lambda: [PREFIX + str(i) for i in range(17)], lambda: ['WireGuardManager']]
        for names in cases:
            value = WireGuardReader('Windows', names, ServiceFixture(), [BINARY], lambda *args: SHA).collect()
            self.assertFalse(value['complete']); self.assertNotEqual(select_service(value)[0], 'healthy')
        value = observed(); value['services'][0]['verified'] = 'true'
        self.assertNotEqual(select_service(value)[0], 'healthy')
        unsafe = self.reader(digest=lambda *args: (_ for _ in ()).throw(AccountError('fixture unsafe path'))).collect()
        self.assertEqual(unsafe['services'][0]['error'], 'unsafe-service-path')
        self.assertNotEqual(select_service(unsafe)[0], 'healthy')

    def test_target_requires_this_service_and_this_route_not_any_other_vpn(self):
        with tempfile.TemporaryDirectory() as home:
            settings = target(mode='tun', client='wireguard', wireguard_service=SERVICE)
            value = wireguard_report(home, settings)
            found = {f['id']: f for f in value['findings']}
            self.assertEqual(found['target.wireguard']['status'], 'pass')
            self.assertEqual(found['target.tun_route']['status'], 'pass')
            self.assertIn('target.wireguard', value['environment']['required'])
            failed = wireguard_report(home, settings, route='Other VPN')
            self.assertEqual(next(f['status'] for f in failed['findings'] if f['id'] == 'target.tun_route'), 'fail')
            incomplete = observed(); incomplete['services'][0]['error'] = 'permission_denied'
            failed = wireguard_report(home, settings, incomplete)
            found = {f['id']: f for f in failed['findings']}
            self.assertEqual(found['target.wireguard']['status'], 'unknown')
            self.assertEqual(found['target.tun_route']['status'], 'unknown')
            self.assertNotEqual(failed['assessment']['verdict'], 'qualified_in_scope')

    def test_settings_fingerprint_and_non_wireguard_compatibility(self):
        old = target()
        legacy = hashlib.sha256(json.dumps({k: old.get(k) for k in sorted(FIELDS - {'wireguard_service'})}, sort_keys=True).encode()).hexdigest()
        self.assertEqual(fingerprint(old), legacy)
        settings = target(mode='tun', client='wireguard', wireguard_service=SERVICE)
        self.assertNotEqual(fingerprint(settings), fingerprint({**settings, 'wireguard_service': PREFIX+'another'}))
        for changes in ({'connection_mode': 'http_proxy'}, {'wireguard_service': 'other'}, {'client': 'auto'}):
            with self.assertRaises(ValueError): validate_settings({**settings, **changes})
        guarded = plan(target(mode='tun', client='wireguard', protection='guarded', ipv6_mode='disabled'))
        self.assertIn('target.wireguard', guarded['required'])
        self.assertNotIn('baseline.rules', guarded['required'])
        self.assertIn('baseline.guard', guarded['required'])

    def test_conflicting_interface_identifiers_and_selective_scope(self):
        with tempfile.TemporaryDirectory() as home:
            settings = target(mode='tun', client='wireguard', wireguard_service=SERVICE)
            rows = wireguard_findings(home, settings)
            route = next(f for f in rows if f.id == 'extra.target_route').evidence[0]
            route['interface'] = 'Other VPN'  # A correct numeric index cannot hide a conflicting name.
            value = make_report(rows, fixture_policy(settings), 'one-click-desktop', settings)
            self.assertEqual(next(f['status'] for f in value['findings'] if f['id'] == 'target.tun_route'), 'fail')
            value = make_report(rows, fixture_policy(settings), 'one-click-desktop', settings, ['target.wireguard'])
            self.assertEqual(next(f['status'] for f in value['findings'] if f['id'] == 'target.wireguard'), 'pass')
            self.assertEqual(next(f['status'] for f in value['findings'] if f['id'] == 'target.tun_route'), 'skipped')
            self.assertNotEqual(value['assessment']['verdict'], 'qualified_in_scope')

    def test_service_changes_after_review_cannot_enable_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve(); store = StateStore(home/'state')
            settings = target(usage='desktop', mode='tun', client='wireguard', wireguard_service=SERVICE, usage_country='US')
            store.save_settings({k: v for k, v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
            io, scheduler = GuardIOFixture(), GuardSchedulerFixture()
            io.observation.update(wireguard=observed(), interfaces=[{'name': 'EnvScope Fixture US', 'up': True}])
            guard = ProcessGuard(store, home, io, scheduler)
            current = wireguard_report(home, store.settings()); prepared = guard.prepare_from_report(current)
            self.assertEqual(prepared['state'], 'planned')
            io.observation['wireguard']['services'][0]['sha256'] = 'a' * 64
            self.assertEqual(guard.enable(prepared['plan_id'], current, True)['state'], 'retest_required')
            self.assertFalse(scheduler.calls); self.assertFalse(guard.config())

    def test_guard_pins_service_binary_and_stops_on_loss_without_restarting_vpn(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve(); store = StateStore(home/'state')
            settings = target(usage='desktop', mode='tun', client='wireguard', wireguard_service=SERVICE, usage_country='US')
            store.save_settings({k: v for k, v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
            io, scheduler = GuardIOFixture(), GuardSchedulerFixture()
            io.observation.update(wireguard=observed(), interfaces=[{'name': 'EnvScope Fixture US', 'up': True}, {'name': 'Other VPN', 'up': True}])
            guard = ProcessGuard(store, home, io, scheduler)
            current = wireguard_report(home, store.settings()); prepared = guard.prepare_from_report(current)
            self.assertEqual(prepared['state'], 'planned', prepared)
            self.assertEqual(scheduler.calls, [])
            self.assertEqual(guard.enable(prepared['plan_id'], current, 'true')['state'], 'confirmation_required')
            self.assertEqual(guard.enable(prepared['plan_id'], current, True)['state'], 'enabled')
            guard.pulse(); self.assertEqual(guard.status()['state'], 'armed')
            baseline = guard.config()['baseline']; validate_baseline(baseline)
            self.assertEqual(baseline['wireguard']['service'], SERVICE)
            for change in ('offline', 'binary', 'interface', 'permission'):
                io.observation.update(wireguard=observed(), targets=[{'pid': 77}], interfaces=[{'name': 'Other VPN', 'up': True}, {'name': 'EnvScope Fixture US', 'up': change != 'interface'}])
                row = io.observation['wireguard']['services'][0]
                if change == 'offline': row.update(state='stopped', verified=False)
                if change == 'binary': row['sha256'] = 'a' * 64
                if change == 'permission': row['error'] = 'permission_denied'
                self.assertFalse(health(baseline, io.snapshot(), io)[0], change)
                self.assertEqual(guard.pulse()['state'], 'blocked', change)
            self.assertEqual(len(io.stops), 4)
            guard.disable(True); self.assertFalse(guard.status()['enabled'])

    def test_read_only_options_use_injected_inventory_and_parameter_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary); store = StateStore(home/'state')
            value = observed()
            ops = Operations(store, home, environment_reader=lambda: {'network': {'wireguard': value}})
            self.assertEqual(ops.run('wireguard-options', {}), value)
            self.assertFalse((store.root/'settings.private.json').exists())
            with self.assertRaises(ValueError): ops.run('wireguard-options', {'service': 'arbitrary'})

    def test_permission_entry_is_scoped_reviewed_and_never_claims_authorization(self):
        value = observed(); value['services'][0]['error'] = 'permission_denied'
        report = {'report_id': 'fixture', 'findings': [finding(value).to_dict()]}
        params = {'report_id': 'fixture', 'finding_id': 'target.wireguard'}
        calls = []
        runner = lambda command, **kw: calls.append(command)
        self.assertEqual(permission_help(report, params, Path('.'), Path('.'), 'true', runner, 'Windows')['state'], 'confirmation_required')
        self.assertFalse(calls)
        response = permission_help(report, params, Path('.'), Path('.'), True, runner, 'Windows')
        self.assertFalse(response['permission_granted']); self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0][0]).name, 'mmc.exe'); self.assertEqual(Path(calls[0][1]).name, 'services.msc')
        self.assertNotIn('/tunnelservice', str(calls))
        shared = redact(report)
        self.assertNotIn(SERVICE, json.dumps(shared)); self.assertNotIn('EnvScope Fixture US', json.dumps(shared))


if __name__ == '__main__': unittest.main()
