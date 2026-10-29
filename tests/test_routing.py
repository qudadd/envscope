from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import TestCase, skipUnless
from unittest.mock import patch

from envscope.discovery import config_directories
from envscope.local_controller import LocalController, from_config, discover
from envscope.model import make_report
from envscope.operations import Operations
from envscope.policy import Policy
from envscope.routing import Routing, FILES, expected_runtime
from envscope.routing_config import load_yaml, plain, rule_strings, update_script, update_yaml_rules, START, END
from envscope.state import StateStore
from scripts.environment_fixtures import fixture, target


class CoreFixture:
    identity = 'fixture-local-core'

    def __init__(self):
        self.calls = []
        self.fail_load = self.reject_rules = self.crash_load = False
        self.value = {'configs': {'mode': 'rule'}, 'rules': {'rules': [{'type': 'Match', 'payload': '', 'proxy': 'DIRECT'}]},
                      'proxies': {'proxies': {'Claude': {'type': 'Selector', 'all': ['node'], 'now': 'node'},
                                              'node': {'type': 'Shadowsocks', 'udp': True}}}}

    def snapshot(self):
        return deepcopy(self.value)

    def reload(self, path):
        self.calls.append(str(path))
        _, config = load_yaml(path.read_bytes())
        if self.crash_load:
            self.crash_load = False
            raise KeyboardInterrupt('simulated termination')
        if self.fail_load:
            raise ValueError('fixture refused loading')
        if len(config['rules']) > 1:
            group = config['rules'][3].split(',')[-1]
            policy = 'reject' if config['rules'][0].endswith(',REJECT') else 'proxy'
            if not self.reject_rules:
                self.value['rules'] = expected_runtime(group, policy)
        else:
            self.value['rules'] = {'rules': [{'type': 'Match', 'payload': '', 'proxy': 'DIRECT'}]}


def setup_fixture(home, system='Windows'):
    store = StateStore(home / 'state')
    settings = target(system, 'desktop', 'tun', usage_country='US', country='US', proxy_group='Claude')
    store.save_settings({k: v for k, v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
    directory = config_directories(home, system, {})[0]
    (directory / 'profiles').mkdir(parents=True)
    (directory / 'profiles.yaml').write_text('current: example\nitems:\n- uid: Script\n  type: script\n  file: Script.js\n', encoding='utf-8')
    (directory / FILES['script']).write_bytes(b'// user comment\nfunction main(config, name) { config.label = name; return config; }\n')
    (directory / FILES['runtime']).write_text('''# preserve this comment
mode: rule
external-controller: 127.0.0.1:9090
secret: "private fixture secret"
proxy-groups:
- name: Claude
  type: select
  proxies: [node]
proxies:
- name: node
  type: ss
  password: private-fixture-password
rules:
- MATCH,DIRECT
''', encoding='utf-8')
    core = CoreFixture()
    routing = Routing(store, home, system, {}, lambda _: core)
    return store, directory, core, routing


class RoutingTests(TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve()
        self.store, self.directory, self.core, self.route = setup_fixture(self.home)

    def report(self):
        return make_report(fixture(self.home, self.store.settings()), Policy(), 'one-click-desktop', self.store.settings())

    def prepare(self):
        report = self.report()
        plan = self.route.prepare(report)
        self.assertEqual(plan['state'], 'planned', plan)
        return report, plan

    def test_readonly_preview_and_boolean_confirmation(self):
        before = {key: (self.directory / value).read_bytes() for key, value in FILES.items()}
        report, plan = self.prepare()
        self.assertEqual(len(plan['rules']), 16)
        self.assertFalse(self.core.calls); self.assertFalse(self.route.root.exists())
        for value in (False, 'true', 1, None):
            self.assertEqual(self.route.apply(plan['plan_id'], report, value)['state'], 'confirmation_required')
        self.assertEqual(before, {key: (self.directory / value).read_bytes() for key, value in FILES.items()})
        self.assertNotIn('private-fixture', json.dumps(plan))

    def test_apply_verify_and_restart_undo_preserve_exact_original_bytes(self):
        before = {key: (self.directory / value).read_bytes() for key, value in FILES.items()}
        report, plan = self.prepare()
        result = self.route.apply(plan['plan_id'], report, True)
        self.assertEqual(result['state'], 'completed', result)
        self.assertEqual(result['verification']['scope'], 'runtime-configuration-only')
        self.assertEqual(self.route.status()['state'], 'committed')
        restarted = Routing(self.store, self.home, 'Windows', {}, lambda _: self.core)
        undo = restarted.undo_prepare()
        self.assertEqual(undo['state'], 'planned')
        self.assertEqual(restarted.undo(undo['plan_id'], 'true')['state'], 'confirmation_required')
        self.assertEqual(restarted.undo(undo['plan_id'], True)['state'], 'rolled_back')
        self.assertEqual(before, {key: (self.directory / value).read_bytes() for key, value in FILES.items()})
        events = ''.join(f.read_text(encoding='utf-8') for f in (self.route.root / 'events').glob('*.jsonl'))
        self.assertIn('committed', events); self.assertIn('rolled_back', events)
        self.assertNotIn('private fixture', events)

    def test_client_ignores_rules_triggers_verified_rollback(self):
        report, plan = self.prepare(); self.core.reject_rules = True
        self.assertEqual(self.route.apply(plan['plan_id'], report, True)['state'], 'rolled_back')
        self.assertEqual(len(self.core.calls), 2)

    def test_offline_core_leaves_partial_record_and_can_recover_later(self):
        report, plan = self.prepare(); self.core.fail_load = True
        self.assertEqual(self.route.apply(plan['plan_id'], report, True)['state'], 'partial')
        self.assertEqual(self.route.prepare(self.report())['state'], 'guided')
        self.core.fail_load = False
        undo = self.route.undo_prepare()
        self.assertEqual(self.route.undo(undo['plan_id'], True)['state'], 'rolled_back')

    def test_interrupted_write_is_recoverable_without_reapplying(self):
        report, plan = self.prepare(); self.core.crash_load = True
        with self.assertRaises(KeyboardInterrupt):
            self.route.apply(plan['plan_id'], report, True)
        self.assertEqual(self.route.status()['state'], 'writing')
        restarted = Routing(self.store, self.home, 'Windows', {}, lambda _: self.core)
        undo = restarted.undo_prepare()
        self.assertEqual(restarted.undo(undo['plan_id'], True)['state'], 'rolled_back')

    def test_external_edits_block_apply_and_undo_without_overwrite(self):
        report, plan = self.prepare()
        path = self.directory / FILES['script']; original = path.read_bytes()
        path.write_bytes(original + b'// later edit\n')
        with self.assertRaisesRegex(ValueError, '变化'):
            self.route.apply(plan['plan_id'], report, True)
        self.assertFalse(self.core.calls)
        report, plan = self.prepare(); self.route.apply(plan['plan_id'], report, True)
        path.write_bytes(path.read_bytes() + b'// another later edit\n')
        self.assertEqual(self.route.undo_prepare()['state'], 'guided')
        self.assertTrue(path.read_bytes().endswith(b'// another later edit\n'))

    def test_changed_target_node_report_expiry_and_other_client_block_writes(self):
        report, plan = self.prepare()
        self.core.value['proxies']['proxies']['Claude']['now'] = 'DIRECT'
        with self.assertRaises(ValueError): self.route.apply(plan['plan_id'], report, True)
        self.assertFalse(self.core.calls)
        self.core.value['proxies']['proxies']['Claude']['now'] = 'node'
        report, plan = self.prepare(); self.route.plans[plan['plan_id']]['deadline'] = 0
        self.assertEqual(self.route.apply(plan['plan_id'], report, True)['state'], 'retest_required')
        self.store.save_settings({'client': 'surge'})
        self.assertEqual(self.route.prepare(self.report())['state'], 'guided')

    def test_unsupported_country_unknown_and_global_mode_never_written(self):
        for country in ('CN', 'RU', ''):
            self.store.save_settings({'usage_country': country}, confirm_environment=True)
            self.assertEqual(self.route.prepare(self.report())['state'], 'guided')
        self.store.save_settings({'usage_country': 'US'}, confirm_environment=True)
        self.core.value['configs']['mode'] = 'global'
        self.assertEqual(self.route.prepare(self.report())['state'], 'guided')
        self.assertFalse(self.core.calls)

    def test_hardlinks_and_corrupt_backup_never_overwrite(self):
        path = self.directory / FILES['script']
        os.link(path, self.directory / 'shared.js')
        self.assertEqual(self.route.prepare(self.report())['state'], 'guided')
        (self.directory / 'shared.js').unlink()
        report, plan = self.prepare(); self.route.apply(plan['plan_id'], report, True)
        record = self.route._record()
        (self.route.root / record['id'] / 'script-before.private.bin').write_bytes(b'corrupt')
        self.assertEqual(self.route.undo_prepare()['state'], 'guided')

    def test_missing_global_profile_and_multiple_directories_need_manual_selection(self):
        profile = self.directory / 'profiles.yaml'
        original = profile.read_bytes(); profile.write_bytes(b'items: []\n')
        self.assertEqual(self.route.options()['state'], 'guided')
        profile.write_bytes(original)
        other = config_directories(self.home, 'Windows', {})[1]
        shutil.copytree(self.directory, other)
        self.assertEqual(self.route.prepare(self.report())['state'], 'guided')

    def test_undo_after_preview_rechecks_every_file(self):
        report, plan = self.prepare(); self.route.apply(plan['plan_id'], report, True)
        undo = self.route.undo_prepare()
        path = self.directory / FILES['runtime']; path.write_bytes(path.read_bytes() + b'# changed\n')
        with self.assertRaises(ValueError): self.route.undo(undo['plan_id'], True)
        self.assertEqual(len(self.core.calls), 1)

    def test_selected_rule_repair_uses_native_not_legacy(self):
        from unittest.mock import Mock
        ops = Operations(self.store, self.home, routing=self.route, legacy=Mock(), discoverer=lambda: [])
        report = self.report()
        report['diagnosis']['problems'] = [{'id': 'maintenance.rules', 'title': 'rules', 'repair': 'routing'}]
        plan = ops.solutions.prepare(report, check_ids=['baseline.rules'])
        self.assertEqual(plan['state'], 'planned', plan)
        result = ops.solutions.apply(plan['plan_id'], report, True)
        self.assertIn(result['state'], ('completed', 'executed'))
        self.assertEqual(len(self.core.calls), 1); ops.legacy.run.assert_not_called()

    def test_combined_repair_keeps_partial_results_when_route_plan_changes(self):
        from unittest.mock import Mock
        ops = Operations(self.store, self.home, routing=self.route, legacy=Mock(), discoverer=lambda: [])
        report = self.report()
        report['diagnosis']['problems'] = [{'id': 'maintenance.rules', 'title': 'rules', 'repair': 'routing'}]
        plan = ops.solutions.prepare(report, check_ids=['baseline.rules'])
        path = self.directory / FILES['script']; path.write_bytes(path.read_bytes() + b'// external edit\n')
        result = ops.solutions.apply(plan['plan_id'], report, True)
        self.assertTrue(result['needs_retest']); self.assertTrue(result['before'])
        self.assertEqual(result['steps'][0]['state'], 'retest_required')
        self.assertFalse(self.core.calls); ops.legacy.run.assert_not_called()


class RoutingConfigTests(TestCase):
    def test_yaml_preserves_other_values_comments_anchors_and_duplicate_rules(self):
        raw = b'# user comment\nmode: rule\nsecret: "secret # spaced"\nproxies: &base [one, two]\ncopy: *base\nrules: [MATCH,DIRECT]\n'
        pinned = rule_strings('Claude', 'reject')
        result = update_yaml_rules(raw, pinned)
        before = plain(load_yaml(raw)[1]); after = plain(load_yaml(result)[1])
        self.assertEqual(after.pop('rules'), pinned + ['MATCH', 'DIRECT'])
        before.pop('rules'); self.assertEqual(before, after)
        self.assertIn(b'# user comment', result); self.assertIn(b'&base', result)
        self.assertEqual(update_yaml_rules(result, pinned), result)

    def test_yaml_rejects_duplicate_multidoc_cycles_tags_depth_and_redacts_errors(self):
        samples = [b'secret: secret-value\nsecret: other\n', b'a: 1\n---\nb: 2', b'a: &a {b: *a}',
                   b'a: !!python/object/apply:os.system [secret-value]', b'a: ' + b'[' * 60 + b'0' + b']' * 60]
        for raw in samples:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError) as caught: load_yaml(raw)
                self.assertNotIn('secret-value', str(caught.exception))

    def test_script_idempotency_migration_and_marker_errors(self):
        raw = b'function main(config) {return {...config};}\n// user line\n'
        pinned = rule_strings('Claude', 'proxy')
        result = update_script(raw, 'Claude', pinned)
        self.assertIn(raw.rstrip(), result)
        self.assertEqual(update_script(result, 'Claude', pinned), result)
        old = raw + b'// >>> claude-switcher managed rules >>>\nold block\n// <<< claude-switcher managed rules <<<\n'
        self.assertEqual(update_script(old, 'Claude', pinned), result)
        for bad in (result + result, raw + START.encode(), b'// no main here\n'):
            with self.assertRaises(ValueError): update_script(bad, 'Claude', pinned)

    @skipUnless(shutil.which('node'), 'Node is needed to check generated user-script composition')
    def test_composed_javascript_runs_after_user_main_and_rejects_missing_group(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'script.cjs'
            source = b'function main(config, name) {return {...config, label:name, rules:["MATCH,DIRECT"]};}\n'
            code = update_script(source, 'Claude', rule_strings('Claude', 'reject'))
            code += b'\nconst c=main({"proxy-groups":[{name:"Claude"}]},"chosen"); if(c.label!=="chosen"||c.rules.length!==17||!c.rules[0].endsWith(",REJECT"))process.exit(2); let threw=false;try{main({});}catch{threw=true;}if(!threw)process.exit(3);'
            path.write_bytes(code)
            subprocess.run(['node', str(path)], check=True, capture_output=True, timeout=10)

    def test_groups_cannot_inject_rule_syntax(self):
        for name in ('DIRECT', 'GLOBAL', 'a,b', 'a\nb', 'a(b)', None, ''):
            with self.assertRaises(ValueError): rule_strings(name, 'proxy')


class LocalControllerTests(TestCase):
    def test_quoted_secret_and_wildcard_only_contacts_loopback(self):
        controller = from_config(load_yaml(b'external-controller: 0.0.0.0:9090\nsecret: "a # b"\n')[1], 'Windows')
        self.assertEqual(controller.origin, 'http://127.0.0.1:9090')
        self.assertEqual(controller.headers['Authorization'], 'Bearer a # b')
        for address in ('example.com:9090', '8.8.8.8:9090', '127.0.0.1:9090/x', 'http://127.0.0.1:9090'):
            with self.assertRaises(ValueError): from_config({'external-controller': address})

    def test_loopback_no_proxy_no_redirect_and_put_readback(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                received.append((self.path, self.headers.get('Authorization')))
                if self.path == '/rules':
                    self.send_response(302); self.send_header('Location', '/leak'); self.end_headers(); return
                self.send_response(200); self.end_headers(); self.wfile.write(b'{"mode":"rule"}')
            def do_PUT(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(204); self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            controller = LocalController('http://127.0.0.1:' + str(server.server_port), 'private-token')
            with patch.dict(os.environ, {'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1'}):
                self.assertEqual(controller.request('/configs'), {'mode': 'rule'})
                with self.assertRaises(ValueError): controller.request('/rules')
                controller.reload(Path(tempfile.gettempdir()) / 'fixture.yaml')
            self.assertEqual(len(received), 3)
            self.assertEqual(received[0][1], 'Bearer private-token')
            self.assertEqual(received[2]['payload'], '')
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_no_guessed_control_port_when_no_config(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError): discover(Path(temp), 'Windows', {})
