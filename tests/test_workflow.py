"""One-stop setup uses a tested local path and fresh, scoped file receipts."""
from copy import deepcopy
import json
from unittest.mock import Mock, patch

from envscope.local_facts import config_shape
from envscope.remedies import SolutionPlans
from tests.test_diagnosis import ConfigurationRepairFixture, finding, report_with, response


class OneStopSetupTests(ConfigurationRepairFixture):
    def plans(self, tester=None, candidates=None):
        legacy = Mock()
        legacy.capabilities.return_value = {"actions": []}
        return SolutionPlans(self.manager, legacy, lambda: candidates if candidates is not None else [{"url": "http://127.0.0.1:7897"}],
                             tester or Mock(return_value={"evidence": [response()]}))

    def report(self, usage="cli", **facts):
        return report_with(finding("extra.cli_env", "pass", [{"installation_count": 1, "config": config_shape(self.manager.paths['cli']), **facts}]),
                           finding("extra.config", "pass", [{"exists": False}, config_shape(self.manager.paths['cli'])]),
                           finding("baseline.reachability", "pass", [response()]), preferences={"usage": usage})

    def write_config(self, value):
        path = self.manager.paths['cli']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding='utf-8')

    def test_no_reported_fault_can_still_prepare_reviewed_setup_and_verify_new_file(self):
        report = self.report()
        self.assertFalse(report['diagnosis']['problems'])
        tester = Mock(return_value={"evidence": [response()]})
        plans = self.plans(tester)
        plan = plans.prepare(report, enhance_cli=True)
        self.assertEqual(plan['configuration_count'], 1)
        self.assertFalse(self.manager.paths['cli'].exists())
        self.assertEqual(plans.apply(plan['plan_id'], report, False)['state'], 'confirmation_required')
        result = plans.apply(plan['plan_id'], report, True)
        self.assertEqual(result['state'], 'executed')
        self.assertEqual(tester.call_count, 2)
        data = json.loads(self.manager.paths['cli'].read_text())
        self.assertEqual(data['env']['HTTPS_PROXY'], 'http://127.0.0.1:7897')
        self.assertEqual(data['env']['NODE_TLS_REJECT_UNAUTHORIZED'], '1')
        receipt = self.manager.verify_receipts(result['before']['configuration'])[0]
        self.assertEqual(receipt['state'], 'verified')
        self.assertEqual(receipt['scope'], 'user-config-file-only')
        self.assertNotIn('after_hash', receipt)
        self.manager.undo(result['backups'][0]['id'], True)
        self.assertFalse(self.manager.paths['cli'].exists())

    def test_setup_preserves_permissions_mcp_credentials_and_internal_bypass(self):
        original = {'permissions': {'deny': ['Read(.env)']}, 'mcpServers': {'local': {'command': 'PRIVATE_MCP'}},
                    'env': {'OTHER': 'PRIVATE_VALUE', 'NO_PROXY': 'internal.example,api.anthropic.com', 'NODE_TLS_REJECT_UNAUTHORIZED': '0'}}
        self.write_config(original)
        plans = self.plans(); report = self.report()
        plan = plans.prepare(report, enhance_cli=True)
        self.assertNotIn('PRIVATE_', json.dumps(plan))
        result = plans.apply(plan['plan_id'], report, True)
        data = json.loads(self.manager.paths['cli'].read_text())
        self.assertEqual(data['mcpServers'], original['mcpServers'])
        self.assertEqual(data['permissions'], original['permissions'])
        self.assertEqual(data['env']['OTHER'], 'PRIVATE_VALUE')
        self.assertEqual(data['env']['NO_PROXY'], 'internal.example')
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_existing_local_code_proxy_is_preferred_over_other_discovered_ports(self):
        self.write_config({'env': {'HTTPS_PROXY': 'http://127.0.0.1:7888'}})
        tester = Mock(return_value={'evidence': [response()]})
        plans = self.plans(tester)
        plans.prepare(self.report(), enhance_cli=True)
        tester.assert_called_once_with('http://127.0.0.1:7888')

    def test_correct_values_are_not_rewritten_just_to_reformat_json(self):
        self.write_config({'env': {'HTTPS_PROXY': 'http://127.0.0.1:7897', 'https_proxy': 'http://127.0.0.1:7897',
                                   'NO_PROXY': '', 'no_proxy': '', 'NODE_TLS_REJECT_UNAUTHORIZED': '1'}})
        before = self.manager.paths['cli'].read_bytes()
        plans = self.plans(); value = plans.prepare(self.report(), enhance_cli=True)
        self.assertEqual(value['state'], 'guided')
        self.assertFalse(plans.plans)
        self.assertEqual(self.manager.paths['cli'].read_bytes(), before)
        self.assertFalse(self.manager.backups.exists())

    def test_explicit_failed_choice_does_not_try_or_fall_back_to_another_path(self):
        tester = Mock(return_value={'evidence': [response(403)]})
        plans = self.plans(tester); report = self.report()
        plan = plans.prepare(report, enhance_cli=True, proxy='http://127.0.0.1:7888')
        tester.assert_called_once_with('http://127.0.0.1:7888')
        self.assertFalse(plan['connections'][0]['verified'])
        self.assertTrue(plan['manual'])
        result = plans.apply(plan['plan_id'], report, True)
        self.assertEqual(json.loads(self.manager.paths['cli'].read_text())['env'], {'NODE_TLS_REJECT_UNAUTHORIZED': '1'})
        self.assertEqual(result['before']['configuration'][0]['fields'], ['NODE_TLS_REJECT_UNAUTHORIZED'])

    def test_incomplete_rejected_or_malformed_api_probe_never_selects_proxy(self):
        variants = [response(403), response(429), response(503), response(error='timeout'), {**response(), 'tls_verified': None},
                    {**response(), 'endpoint': 'https://api.anthropic.com.evil/v1/models'}, {**response(), 'http_status': '401'}, None]
        for item in variants:
            with self.subTest(item=item):
                plans = self.plans(Mock(return_value={'evidence': [item]}))
                plan = plans.prepare(self.report(), enhance_cli=True)
                self.assertFalse(plan['connections'][0]['verified'])
                changes = plans.plans[plan['plan_id']]['changes']
                self.assertNotIn('HTTPS_PROXY', changes[0]['fields'])

    def test_cloud_and_custom_endpoint_are_not_rerouted_even_when_proxy_needs_repair(self):
        for key, value in (('ANTHROPIC_BASE_URL', 'https://gateway.example'), ('CLAUDE_CODE_USE_BEDROCK', '1'),
                           ('CLAUDE_CODE_USE_VERTEX', '1'), ('CLAUDE_CODE_USE_FOUNDRY', '1')):
            with self.subTest(key=key):
                self.write_config({'env': {key: value, 'HTTPS_PROXY': 'socks5://127.0.0.1:7890'}})
                tester = Mock(); plans = self.plans(tester)
                plan = plans.prepare(self.report(proxy_scheme='socks5'), enhance_cli=True)
                tester.assert_not_called()
                self.assertIn('自定义接口或云平台', ' '.join(plan['manual']))
                data = json.loads(plans.plans[plan['plan_id']]['changes'][0]['after'])
                self.assertEqual(data['env'][key], value)
                self.assertEqual(data['env']['HTTPS_PROXY'], 'socks5://127.0.0.1:7890')

    def test_remote_or_authenticated_existing_proxy_is_preserved_without_explicit_choice(self):
        for proxy in ('https://proxy.example:8080', 'http://user:PRIVATE_PASSWORD@127.0.0.1:7897'):
            self.write_config({'env': {'HTTPS_PROXY': proxy}})
            tester = Mock(); plans = self.plans(tester)
            plan = plans.prepare(self.report(), enhance_cli=True)
            tester.assert_not_called()
            self.assertNotIn('PRIVATE_PASSWORD', json.dumps(plan))
            data = json.loads(plans.plans[plan['plan_id']]['changes'][0]['after'])
            self.assertEqual(data['env']['HTTPS_PROXY'], proxy)

    def test_missing_code_is_not_created_for_auto_or_desktop_usage(self):
        for usage in ('auto', 'desktop'):
            plans = self.plans(Mock())
            report = report_with(finding('extra.cli_env', entries=[{'installation_count': 0}]), preferences={'usage': usage})
            self.assertEqual(plans.prepare(report, enhance_cli=True)['state'], 'guided')
            self.assertFalse(self.manager.paths['cli'].exists())
            plans.proxy_tester.assert_not_called()

    def test_invalid_flags_protocols_and_remote_origins_are_rejected(self):
        plans = self.plans(); report = self.report()
        for options in ({'enhance_cli': 'yes'}, {'enhance_cli': 1}, {'enhance_cli': True, 'check_id': 'proxy'},
                        *({'enhance_cli': True, 'proxy': proxy} for proxy in ('socks5://127.0.0.1:7890', 'https://proxy.example:8080',
                           'http://user:pass@127.0.0.1:7897', 'http://127.0.0.1:7897/path', 'http://127.0.0.1:7897/?q=x'))):
            with self.subTest(options=options), self.assertRaises(ValueError):
                plans.prepare(report, **options)

    def test_connection_fails_at_apply_without_any_config_write(self):
        path = self.manager.paths['desktop']; path.write_text('{"mcpServers":{},}', encoding='utf-8')
        report = self.report(); report['diagnosis']['problems'].append({'id': 'config.desktop', 'title': 'fixture', 'repair': 'json-desktop'})
        tester = Mock(side_effect=[{'evidence': [response()]}, {'evidence': [response(407)]}])
        plans = self.plans(tester); plan = plans.prepare(report, enhance_cli=True)
        result = plans.apply(plan['plan_id'], report, True)
        self.assertEqual(result['state'], 'blocked')
        self.assertFalse(result['backups'])
        self.assertEqual(path.read_text(), '{"mcpServers":{},}')
        self.assertFalse(self.manager.paths['cli'].exists())

    def test_changed_inherited_connection_settings_require_new_review(self):
        plans = self.plans(); report = self.report(); plan = plans.prepare(report, enhance_cli=True)
        self.manager.environ['NO_PROXY'] = 'new-internal.example'
        self.assertEqual(plans.apply(plan['plan_id'], report, True)['state'], 'retest_required')
        self.assertFalse(self.manager.paths['cli'].exists())

    def test_slow_prewrite_verification_cannot_extend_plan_validity(self):
        plans = self.plans(); report = self.report(); plan = plans.prepare(report, enhance_cli=True)
        deadline = plans.plans[plan['plan_id']]['deadline']
        with patch('envscope.remedies.time.monotonic', side_effect=[deadline-1, deadline+1]):
            self.assertEqual(plans.apply(plan['plan_id'], report, True)['state'], 'retest_required')
        self.assertFalse(self.manager.paths['cli'].exists())

    def test_receipt_is_a_new_file_read_and_does_not_override_later_edits(self):
        plans = self.plans(); report = self.report(); plan = plans.prepare(report, enhance_cli=True)
        result = plans.apply(plan['plan_id'], report, True)
        receipts = result['before']['configuration']
        self.assertEqual(self.manager.verify_receipts(receipts)[0]['state'], 'verified')
        self.write_config({'env': {'OTHER': 'later edit'}})
        self.assertEqual(self.manager.verify_receipts(receipts)[0]['state'], 'changed')
        with patch('envscope.remedies._read', side_effect=OSError('fixture')):
            self.assertEqual(self.manager.verify_receipts(receipts)[0]['state'], 'unverified')
        self.assertEqual(json.loads(self.manager.paths['cli'].read_text())['env']['OTHER'], 'later edit')
