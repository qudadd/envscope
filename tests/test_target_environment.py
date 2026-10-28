import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.operations import Operations
from envscope.state import StateStore, validate_settings
from envscope.target_environment import plan, suggest, fingerprint
from envscope.remedies import ConfigRemedies, SolutionPlans
from envscope.transport import desktop_transport
from scripts.environment_fixtures import report, target, PROXY


class TargetEnvironmentTests(unittest.TestCase):
    def test_matrix_two_os_four_usages_three_routes(self):
        for system in ('Windows', 'Darwin'):
            for usage in ('web', 'desktop', 'cli', 'both'):
                for mode in ('direct', 'http_proxy', 'tun'):
                    with self.subTest(system=system, usage=usage, mode=mode), tempfile.TemporaryDirectory() as home:
                        r = report(home, target(system, usage, mode), system)
                        self.assertEqual(r['assessment']['verdict'], 'qualified_in_scope', r['assessment'])
                        self.assertNotEqual(r['decision']['verdict'], 'clear_in_scope')
                        self.assertFalse(r['diagnosis']['problems'], r['diagnosis']['problems'])

    def test_faults_never_qualify(self):
        faults = ['missing_cli', 'permission', 'bad_json', 'tls_disabled', 'wrong_proxy', 'provider', 'timezone',
                  'locale', 'dns', 'timeout', 'certificate', 'api_405', 'clock']
        for system in ('Windows', 'Darwin'):
            for fault in faults:
                with self.subTest(system=system, fault=fault), tempfile.TemporaryDirectory() as home:
                    r = report(home, target(system), system, fault)
                    self.assertNotEqual(r['assessment']['verdict'], 'qualified_in_scope', fault)
                    if fault == 'permission':
                        self.assertEqual(next(i['state'] for i in r['assessment']['items'] if i['id'] == 'target.config'), 'permission')

    def test_irrelevant_failures_remain_raw_but_do_not_block_cli(self):
        with tempfile.TemporaryDirectory() as home:
            r = report(home, target(), fault='unrelated_web')
            self.assertEqual(r['assessment']['verdict'], 'qualified_in_scope')
            self.assertTrue(any(f['status'] == 'fail' for f in r['findings']))
            self.assertFalse(r['diagnosis']['problems'], r['diagnosis']['problems'])

    def test_guard_ipv6_cloud_auth_and_web_boundaries(self):
        cases = [(target(usage='web'), 'web_403'), (target(usage='desktop'), 'missing_desktop'),
                 (target(mode='tun', protection='guarded', ipv6_mode='allowlist', allowed_ipv6=['2001:4860::/32']), 'guard'), (target(ipv6_mode='disabled'), None),
                 (target(provider='custom'), None), (target(auth_mode='api_key'), None), (target(mode='tun'), 'physical_route')]
        for settings, fault in cases:
            with self.subTest(settings=settings, fault=fault), tempfile.TemporaryDirectory() as home:
                self.assertNotEqual(report(home, settings, fault=fault)['assessment']['verdict'], 'qualified_in_scope')

    def test_desktop_proxy_bypass_and_wrong_system_route_cannot_pass(self):
        for fault in ('system_bypass', 'system_proxy_mismatch'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as home:
                value = report(home, target(usage='desktop', mode='http_proxy'), fault=fault)
                self.assertEqual(value['assessment']['verdict'], 'needs_fix')
                self.assertEqual(next(f['status'] for f in value['findings'] if f['id']=='target.path'), 'fail')

    def test_code_bypass_diagnosis_only_checks_its_selected_route(self):
        for mode, fault, qualified in (('http_proxy','cli_web_bypass',True), ('http_proxy','cli_api_bypass',False),
                                       ('direct','cli_api_bypass',True)):
            with self.subTest(mode=mode, fault=fault), tempfile.TemporaryDirectory() as home:
                value = report(home, target(usage='both', mode=mode), fault=fault)
                self.assertEqual(value['assessment']['verdict'] == 'qualified_in_scope', qualified, value['assessment'])
                self.assertEqual(any(p['id'] == 'cli.bypass' for p in value['diagnosis']['problems']), not qualified)

    def test_confirmation_persistence_invalidation_and_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory))
            self.assertFalse(store.settings()['environment_confirmed'])

            self.assertIsNone(plan(store.settings()))
            proposed = suggest(store.settings(), {'platform': 'Windows', 'locale': 'zh-CN', 'network': {'timezone_id': 'China Standard Time'}}, {}, [])
            self.assertFalse(store.settings()['environment_confirmed'])
            self.assertEqual(proposed['proposed']['timezone'], 'China Standard Time')
            saved = store.save_settings({'usage': 'cli', 'connection_mode': 'direct'}, confirm_environment=True)
            self.assertTrue(StateStore(Path(directory)).settings()['environment_confirmed'])
            store.save_settings({'usage': 'cli'})
            self.assertTrue(store.settings()['environment_confirmed'])
            store.save_settings({'timezone': 'UTC'})
            self.assertFalse(store.settings()['environment_confirmed'])
            self.assertNotEqual(fingerprint(saved), fingerprint(store.settings()))
            store.restore_settings()
            self.assertFalse(store.settings()['environment_confirmed'])

    def test_strict_tun_with_explicit_ipv6_range_has_measured_gate(self):
        for system in ('Windows', 'Darwin'):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as home:
                settings = target(system, mode='tun', protection='guarded', ipv6_mode='allowlist', allowed_ipv6=['2001:4860::/32'])
                value = report(home, settings, system)
                self.assertEqual(value['assessment']['verdict'], 'qualified_in_scope', value['assessment'])
                failed = report(home, settings, system, 'guard')
                self.assertNotEqual(failed['assessment']['verdict'], 'qualified_in_scope')

    def test_invalid_combinations_and_credentials_rejected(self):
        for changes in ({'usage': 'auto'}, {'connection_mode': 'inherit'}, {'target_proxy': 'http://user:secret@127.0.0.1:7897'},
                        {'usage': 'web', 'provider': 'vertex'}, {'protection': 'guarded'}, {'ipv6_mode': 'allowlist'},
                        {'usage':'cli','language':'en-US'}, {'usage':'web','language':'zh-CN'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                target(**changes)

    def test_selected_transport_never_falls_back(self):
        with patch.dict('os.environ', {'HTTPS_PROXY': PROXY}, clear=True):
            direct = desktop_transport(target())
            self.assertTrue(direct.direct)
            self.assertIsNone(direct.proxy)
            proxy = desktop_transport(target(mode='http_proxy'))
            self.assertEqual(proxy.proxy, PROXY)
            self.assertFalse(proxy.direct)

    def test_repair_recheck_and_byte_exact_undo(self):
        for mode in ('direct', 'http_proxy', 'tun'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                settings = target(mode=mode)
                report(home, settings)
                path = home / '.claude/settings.json'
                before = b'{"env":{"HTTPS_PROXY":"socks5://127.0.0.1:7898","NODE_TLS_REJECT_UNAUTHORIZED":"0"},"mcpServers":{"fixture":{"env":{"SECRET":"FIXTURE_ONLY"}}},}'
                path.write_bytes(before)
                config = ConfigRemedies(home, home / 'desktop', environ={})
                legacy = Mock()
                legacy.capabilities.return_value = {'actions': []}
                tester = Mock(return_value={'evidence': [{'endpoint': 'https://api.anthropic.com/v1/models', 'http_status': 401, 'tls_verified': True}]})
                solutions = SolutionPlans(config, legacy, lambda: [{'url': PROXY}], tester)
                old = report(home, settings)
                prepared = solutions.prepare(old, enhance_cli=True)
                self.assertEqual(prepared['state'], 'planned', prepared)
                self.assertEqual(solutions.apply(prepared['plan_id'], old, False)['state'], 'confirmation_required')
                self.assertEqual(path.read_bytes(), before)
                result = solutions.apply(prepared['plan_id'], old, True)
                self.assertEqual(result['state'], 'executed', result)
                after = report(home, settings)
                self.assertEqual(after['assessment']['verdict'], 'qualified_in_scope', after['assessment'])
                self.assertEqual(json.loads(path.read_text())['mcpServers']['fixture']['env']['SECRET'], 'FIXTURE_ONLY')
                if mode != 'http_proxy':
                    tester.assert_not_called()
                config.undo(result['backups'][0]['id'], True)
                self.assertEqual(path.read_bytes(), before)
                legacy.run.assert_not_called()

    def test_stale_target_refuses_plan_and_launch(self):
        with tempfile.TemporaryDirectory() as home:
            store = StateStore(memory=True)
            settings = target()
            store.save_settings({k:v for k,v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
            r = report(home, settings)
            ops = Operations(store, home, discoverer=lambda: [], legacy=Mock())
            store.save_settings({'timezone': 'UTC'})
            result = ops.run('solution-plan', {'report_id': r['report_id']}, report=r)
            self.assertEqual(result['state'], 'retest_required')

    def test_windows_automatic_flags_query_and_failure_are_distinct(self):
        from envscope.windows_proxy import automatic_proxy_flags
        keys = []
        def query(handle, number, value, size):
            self.assertEqual(number, 75)
            self.assertIsNone(handle)
            self.assertIsNone(value._obj.connection)
            key = value._obj.options[0].option
            keys.append(key)
            if key == 10:
                return 0
            value._obj.options[0].value.number = 8 | 4
            return 1
        self.assertEqual(automatic_proxy_flags(query), {'auto_detect':True,'pac_configured':True,'source':'wininet-lan-flags'})
        self.assertEqual(keys, [10, 1])
        self.assertIsNone(automatic_proxy_flags(lambda *a: 0)['auto_detect'])

    def test_inherited_proxy_is_explained_and_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            settings = target()
            r = report(home, settings, fault='wrong_proxy')
            environ = {'HTTPS_PROXY':PROXY}
            config = ConfigRemedies(home, home/'desktop', environ=environ)
            solutions = SolutionPlans(config, Mock(), Mock(), Mock())
            value = solutions.prepare(r, enhance_cli=True)
            self.assertIn('当前终端仍继承 HTTP 代理', ' '.join(value['manual']))
            self.assertEqual(solutions.apply(value['plan_id'], r, True)['state'], 'executed')
            self.assertEqual(environ, {'HTTPS_PROXY':PROXY})
            solutions.proxy_tester.assert_not_called()

    def test_maintenance_models_api_uses_get_not_head(self):
        from envscope.maintenance import proxy_works
        from envscope.transport import Response
        with patch('envscope.maintenance.CurlTransport') as transport:
            transport.return_value.get.return_value = Response(status=401, tls_verified=True)
            self.assertTrue(proxy_works(PROXY))
            transport.return_value.get.assert_called_once_with('https://api.anthropic.com/v1/models')
