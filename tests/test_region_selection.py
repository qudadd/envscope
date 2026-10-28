import base64
import json
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import TestCase
from unittest.mock import Mock, patch

from envscope.check_catalog import check_catalog
from envscope.inspection import ids, resolve, validate_selection
from envscope.model import make_report
from envscope.operations import Operations
from envscope.policy import Policy
from envscope.probes import audit
from envscope.region_profiles import profile, profiles
from envscope.region_setup import RegionSetup, NodeController, discover_controller, set_system_value
from envscope.state import StateStore, validate_settings
from scripts.environment_fixtures import fixture, target


class RegionSelectionTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.store = StateStore(self.home / 'state')
        selected = profile('us-los-angeles', 'Windows')
        values = target(usage_country='US', region_profile=selected['id'], **{k: selected[k] for k in ('country', 'timezone', 'locale')})
        self.store.save_settings({k: v for k, v in values.items() if k != 'environment_confirmed'}, confirm_environment=True)
        self.inventory = {'platform': 'Windows', 'locale': 'zh-CN', 'network': {'timezone_id': 'China Standard Time'}}
        self.writes = []
        def write(key, value):
            self.writes.append((key, value))
            if key == 'locale':
                self.inventory['locale'] = value
            else:
                self.inventory['network']['timezone_id'] = value
        self.region = RegionSetup(self.store, lambda: self.inventory, self.home, 'Windows', write,
                                  Mock(side_effect=ValueError('fixture: no controller')))

    def report(self, checks=None, fault=None):
        settings = self.store.settings()
        values = fixture(self.home, settings, fault=fault)
        return make_report(values, Policy(), 'one-click-desktop', settings, checks)

    def test_presets_do_not_infer_physical_location_and_us_has_multiple_cities(self):
        options = profiles('Windows')
        self.assertGreater(len([p for p in options if p['country'] == 'US']), 1)
        self.assertNotIn('usage_country', options[0])
        self.assertEqual(profile('us-new-york', 'Darwin')['timezone'], 'America/New_York')
        values = self.store.settings()
        values['timezone'] = 'China Standard Time'
        with self.assertRaises(ValueError):
            validate_settings(values)

    def test_presets_change_targets_only_and_custom_settings_detach_preset(self):
        self.assertFalse(self.writes)
        self.store.save_settings({'timezone': 'UTC'})
        self.assertEqual(self.store.settings()['region_profile'], '')
        self.assertFalse(self.store.settings()['environment_confirmed'])

    def test_region_preview_confirmation_readback_persisted_undo(self):
        report = self.report()
        plan = self.region.prepare(report, ['timezone', 'locale'])
        self.assertEqual(plan['state'], 'planned')
        self.assertEqual(self.region.apply(plan['plan_id'], report, False)['state'], 'confirmation_required')
        self.assertFalse(self.writes)
        result = self.region.apply(plan['plan_id'], report, True)
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(len(self.writes), 2)
        restarted = RegionSetup(self.store, self.region.reader, self.home, 'Windows', self.region.writer)
        self.assertEqual(restarted.recovery()['before']['timezone'], 'China Standard Time')
        self.assertEqual(restarted.undo(True)['state'], 'completed')
        self.assertEqual(self.inventory['locale'], 'zh-CN')
        self.assertIsNone(restarted.recovery())

    def test_region_denial_stops_later_steps_and_records_original(self):
        report = self.report()
        plan = self.region.prepare(report, ['timezone', 'locale'])
        self.region.writer = Mock(side_effect=ValueError('cancelled'))
        value = self.region.apply(plan['plan_id'], report, True)
        self.assertEqual(value['state'], 'partial')
        self.region.writer.assert_called_once_with('timezone', 'Pacific Standard Time')
        self.assertEqual(self.region.recovery()['before']['locale'], 'zh-CN')

    def test_command_success_without_readback_is_not_success(self):
        report = self.report()
        plan = self.region.prepare(report, ['timezone'])
        self.region.writer = Mock()
        self.assertEqual(self.region.apply(plan['plan_id'], report, True)['state'], 'partial')

    def test_changed_live_settings_and_changed_goal_refuse_old_plan(self):
        report = self.report()
        plan = self.region.prepare(report, ['timezone'])
        self.inventory['network']['timezone_id'] = 'UTC'
        self.assertEqual(self.region.apply(plan['plan_id'], report, True)['state'], 'retest_required')
        self.assertFalse(self.writes)
        self.store.save_settings({'usage_country': 'JP'}, confirm_environment=True)
        self.assertEqual(self.region.apply(plan['plan_id'], report, True)['state'], 'retest_required')

    def test_undo_never_overwrites_later_user_edit(self):
        report = self.report()
        plan = self.region.prepare(report, ['timezone'])
        self.region.apply(plan['plan_id'], report, True)
        self.inventory['network']['timezone_id'] = 'UTC'
        before = len(self.writes)
        self.assertEqual(self.region.undo(True)['state'], 'partial')
        self.assertEqual(len(self.writes), before)

    def test_cn_ru_and_unknown_physical_location_cannot_be_overridden_by_us_preset(self):
        for actual in ('CN', 'RU', ''):
            self.store.save_settings({'usage_country': actual}, confirm_environment=True)
            plan = self.region.prepare(self.report(), ['timezone'])
            self.assertEqual(plan['state'], 'blocked')
        self.assertFalse(self.writes)

    def test_partial_countries_require_manual_review(self):
        self.store.save_settings({'usage_country': 'UA'}, confirm_environment=True)
        self.assertEqual(self.region.prepare(self.report(), ['timezone'])['state'], 'blocked')

    def test_injection_and_unknown_properties_never_reach_command_runner(self):
        runner = Mock()
        for system, key, value in (('Windows', 'timezone', 'UTC;whoami'), ('Darwin', 'timezone', 'Asia/Tokyo -setremotelogin on'),
                                   ('Windows', 'locale', 'en-US\nwhoami'), ('Darwin', 'unexpected', 'US')):
            with self.subTest(system=system, value=value), self.assertRaises(ValueError):
                set_system_value(system, key, value, runner)
        runner.assert_not_called()

    def test_native_command_allowlist_and_elevation_scope(self):
        runner = Mock(return_value=Mock(returncode=0))
        set_system_value('Windows', 'locale', 'en-US', runner)
        args = runner.call_args.args[0]
        script = base64.b64decode(args[-1]).decode('utf-16-le')
        self.assertIn("Set-Culture -CultureInfo 'en-US'", script)
        self.assertNotIn('RunAs', script)
        runner.side_effect = [Mock(returncode=1), Mock(returncode=0)]
        set_system_value('Windows', 'timezone', 'Pacific Standard Time', runner)
        elevated = base64.b64decode(runner.call_args.args[0][-1]).decode('utf-16-le')
        self.assertIn('tzutil.exe', elevated)
        self.assertIn('-Verb RunAs -WindowStyle Hidden', elevated)
        runner.side_effect = None
        set_system_value('Darwin', 'timezone', 'America/New_York', runner)
        self.assertEqual(runner.call_args.args[0], ['/usr/bin/osascript', '-e', 'do shell script "/usr/sbin/systemsetup -settimezone America/New_York" with administrator privileges'])

    def test_selection_catalog_is_complete_and_validated(self):
        self.assertEqual({r['id'] for r in check_catalog()}, ids())
        for invalid in ([], ['extra.clock'] * 2, ['arbitrary.command'], 'all', [True]):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                validate_selection(invalid)
        enabled = resolve(['target.tls'])
        self.assertIn('baseline.reachability', enabled)
        self.assertNotIn('udp.stun', enabled)

    def test_timezone_selection_does_not_run_unselected_network_or_device_probes(self):
        with patch('envscope.probes.collect', return_value=self.inventory), \
                patch('envscope.probes.local_snapshot', return_value={}), \
                patch('envscope.probes.bounded_facts') as network, \
                patch('envscope.probes.http_observations') as http, \
                patch('envscope.probes.stun_observations') as stun, \
                patch('envscope.baseline.extra_network') as extra, \
                patch('envscope.baseline.runtime_rules') as controller, \
                patch('envscope.baseline.guard_state') as guard, \
                patch('envscope.environment_info.device_information') as device:
            values = audit(Policy(), Mock(), online=True, ipv6=True, stun=True, baseline_config=self.store.settings(), selected_checks=['baseline.timezone'])
        for probe in (network, http, stun, extra, controller, guard, device):
            probe.assert_not_called()
        report = make_report(values, Policy(), 'one-click-desktop', self.store.settings(), ['baseline.timezone'])
        self.assertEqual(next(f['status'] for f in report['findings'] if f['id'] == 'http.egress'), 'skipped')
        self.assertNotEqual(report['assessment']['verdict'], 'qualified_in_scope')
        self.assertEqual(next(f['state'] for f in report['assessment']['items'] if f['id'] == 'extra.cli_env'), 'unavailable')

    def test_partial_checks_cannot_mask_region_failure(self):
        self.store.save_settings({'usage_country': 'CN'}, confirm_environment=True)
        report = self.report(['baseline.timezone'])
        self.assertEqual(next(f['status'] for f in report['findings'] if f['id'] == 'target.region'), 'fail')
        self.assertEqual(report['assessment']['verdict'], 'needs_fix')

    def test_bulk_repair_is_bound_to_selected_checks_and_latest_report(self):
        ops = Operations(self.store, self.home, discoverer=lambda: [], environment_reader=lambda: self.inventory)
        ops.regions = self.region
        report = self.report(['baseline.timezone'])
        params = {'report_id': report['report_id'], 'check_ids': ['baseline.timezone']}
        value = ops.run('inspection-plan', params, report=report)
        self.assertEqual(value['state'], 'planned')
        self.assertFalse(self.writes)
        self.assertEqual(ops.run('inspection-apply', {'plan_id': value['plan_id']}, report=report)['state'], 'confirmation_required')
        self.assertEqual(ops.run('inspection-apply', {'plan_id': value['plan_id']}, confirmed=True, report=report)['state'], 'completed')
        self.assertEqual([k for k, _ in self.writes], ['timezone'])
        self.assertEqual(ops.run('inspection-plan', {**params, 'check_ids': ['extra.config']}, report=report)['state'], 'retest_required')
        self.assertEqual(ops.run('inspection-plan', {**params, 'report_id': 'old'}, report=report)['state'], 'retest_required')

    def test_select_all_can_prepare_without_irrelevant_target_rows_blocking_it(self):
        ops = Operations(self.store, self.home, discoverer=lambda: [], environment_reader=lambda: self.inventory)
        ops.regions = self.region
        report = self.report()
        value = ops.run('inspection-plan', {'report_id': report['report_id'], 'check_ids': sorted(ids())}, report=report)
        self.assertEqual(value['state'], 'planned')
        self.assertTrue(value['manual_items'])
        self.assertFalse(self.writes)

    def test_pending_region_recovery_is_not_replaced_by_another_plan(self):
        report = self.report()
        plan = self.region.prepare(report, ['timezone'])
        self.region.writer = Mock(side_effect=ValueError('cancel'))
        self.region.apply(plan['plan_id'], report, True)
        original = self.region.recovery()
        self.assertEqual(self.region.prepare(report, ['locale'])['state'], 'guided')
        self.assertEqual(self.region.recovery(), original)


class ControllerSelectionTests(TestCase):
    def test_loopback_node_switch_readback_and_stale_membership(self):
        state = {'now': 'DIRECT', 'puts': [], 'auth': []}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                state['auth'].append(self.headers.get('Authorization'))
                body = json.dumps({'proxies': {'地区 / Claude': {'type': 'Selector', 'now': state['now'], 'all': ['DIRECT', 'US 节点', '自动']},
                                               'DIRECT': {'type': 'Direct'}, 'US 节点': {'type': 'Shadowsocks'}, '自动': {'type': 'URLTest', 'all': []}}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            def do_PUT(self):
                state['puts'].append(self.path)
                state['now'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))['name']
                self.send_response(204)
                self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = NodeController('http://127.0.0.1:' + str(server.server_port), 'FIXTURE')
            self.assertEqual(client.groups()[0]['nodes'], ['US 节点'])
            client.select('地区 / Claude', 'US 节点', 'DIRECT')
            self.assertEqual(state['now'], 'US 节点')
            self.assertIn('%2F', state['puts'][0])
            with self.assertRaises(ValueError):
                client.select('地区 / Claude', 'US 节点', 'DIRECT')
            client.select('地区 / Claude', 'DIRECT', 'US 节点', restore=True)
            self.assertEqual(state['now'], 'DIRECT')
            self.assertTrue(all(s == 'Bearer FIXTURE' for s in state['auth']))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_writable_controller_is_explicit_and_loopback_only(self):
        for origin in ('http://example.com:9090', 'http://127.0.0.1:9090/path', 'http://user:pw@127.0.0.1:9090', 'https://127.0.0.1:9090'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                NodeController(origin)
        with patch('envscope.region_setup.config_documents', return_value=[]), self.assertRaises(ValueError):
            discover_controller(environ={})

    def test_node_names_are_never_geolocation_evidence(self):
        from envscope.regions import region_finding
        value = region_finding([], {'usage_country': 'US', 'country': 'US', 'proxy_node': 'US Los Angeles'})
        self.assertNotEqual(value.status.value, 'pass')

    def test_malformed_controller_payload_is_rejected(self):
        client = NodeController('http://127.0.0.1:9090')
        client.request = Mock(return_value=[])
        with self.assertRaises(ValueError):
            client.groups()
