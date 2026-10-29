"""Additional measurements use synthetic input, temporary files and loopback only."""
import base64
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import format_datetime
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.baseline import guard_state
from envscope.extended import CHECKS, extended_checks
from envscope.local_facts import (account_markers, bypass_matches, cli_facts, config_shape,
                                 hosts_overrides, local_snapshot, probe_listeners, read_system_proxy)
from envscope.network_facts import collect_facts, lookup_routes, parse_mac_route, resolve_host, main as network_main, bounded_facts
from envscope.model import Status, Finding
from envscope.policy import Policy
from envscope.probes import audit
from envscope.transport import MARKER, CurlTransport


def fixtures():
    inventory = {"network": {"adapters": [{"Name": "tun0", "ifIndex": 8, "InterfaceDescription": "Wintun"}]}}
    network = {"dns": [{"host": h, "addresses": ["8.8.8.8"], "complete": True} for h in ("claude.ai", "api.anthropic.com")],
               "routes": [{"destination": "8.8.8.8", "interface": "tun0", "interface_index": 8}]}
    local = {"hosts": {"readable": True, "overrides": []}, "proxy": {"system": {"available": True, "endpoints": [], "bypass": {}}, "environment": []},
             "listeners": [{"endpoint": "http://127.0.0.1:7897", "tcp_accepts": True}], "controller": {"found": True, "wildcard_bind": False, "loopback_bind": True},
             "installed": True, "profile_exists": True, "desktop_config": {"exists": True, "valid": True},
             "cli": {"installation_count": 1, "endpoint_valid": True, "endpoint_https_or_local": True, "api_key_present": True},
             "storage": {"free_bytes": 2 * 1024 ** 3}, "account": {"valid": True, "pending": []}}
    responses = [{"endpoint": endpoint, "tls_verified": True, "clock_offset_seconds": offset, "timings": {"total_ms": 100}, "error": ""}
                 for endpoint, offset in (("https://claude.ai/", 2), ("https://api.anthropic.com/", 3))]
    context = {"runtime": {"tun_enabled": True}, "responses": responses}
    return inventory, network, local, context


def evaluate(values):
    return {f.id: f for f in extended_checks(*values)}


class ExtendedRuleTests(unittest.TestCase):
    def test_eighteen_distinct_measurements_have_scopes_and_suggestions(self):
        by_id = evaluate(fixtures())
        self.assertEqual(len(by_id), 18)
        self.assertEqual(set(by_id), {"extra." + name for name, _ in CHECKS})
        self.assertTrue(all(f.scope and f.limitations and f.suggestion for f in by_id.values()))
        self.assertEqual(by_id["extra.target_route"].status, Status.PASS)
        self.assertEqual(by_id["extra.tls"].status, Status.PASS)

    def test_silence_malformed_and_duplicate_dns_cannot_pass(self):
        for dns in ([], [{"host": "claude.ai", "addresses": ["8.8.8.8"], "complete": True}] * 2,
                    [{"host": h, "addresses": ["garbage", "8.8.8.8"], "complete": True} for h in ("claude.ai", "api.anthropic.com")]):
            values = list(fixtures())
            values[1]["dns"] = dns
            self.assertNotEqual(evaluate(values)["extra.dns_resolution"].status, Status.PASS)
            self.assertNotEqual(evaluate(values)["extra.target_route"].status, Status.PASS)

    def test_fake_ip_is_configuration_signal_not_leak_failure(self):
        values = list(fixtures())
        for item in values[1]["dns"]:
            item["addresses"] = ["198.18.0.3"]
        self.assertEqual(evaluate(values)["extra.dns_resolution"].status, Status.PASS)
        values[1]["dns"][0]["addresses"] = ["127.0.0.1"]
        self.assertEqual(evaluate(values)["extra.dns_resolution"].status, Status.WARN)

    def test_route_does_not_pass_for_physical_missing_ipv6_or_reject(self):
        for update in ({"interface": "Ethernet", "interface_index": 9}, {"error": "timeout"}, {"flags": "<UP,REJECT>"}):
            values = list(fixtures())
            values[1]["routes"][0].update(update)
            self.assertNotEqual(evaluate(values)["extra.target_route"].status, Status.PASS)
        values = list(fixtures())
        values[1]["dns"][0]["addresses"].append("2001:4860:4860::8888")
        self.assertNotEqual(evaluate(values)["extra.target_route"].status, Status.PASS)

    def test_route_matches_known_name_or_positive_index_without_missing_index_alias(self):
        values = list(fixtures())
        del values[1]["routes"][0]["interface"]
        self.assertEqual(evaluate(values)["extra.target_route"].status, Status.PASS)
        values[0]["network"]["adapters"] = [{"name": "utun3"}]
        values[1]["routes"] = [{"destination": "8.8.8.8", "interface": "en0"}]
        self.assertNotEqual(evaluate(values)["extra.target_route"].status, Status.PASS)
        values[1]["routes"][0]["interface"] = "utun3"
        self.assertEqual(evaluate(values)["extra.target_route"].status, Status.PASS)

    def test_proxy_difference_bypass_listener_and_pac_are_distinct(self):
        values = list(fixtures())
        values[2]["proxy"]["system"].update(endpoints=["http://127.0.0.1:7897"], bypass={"target_matches": ["claude.ai"]})
        values[2]["listeners"][0]["tcp_accepts"] = False
        result = evaluate(values)
        for key in ("proxy_layers", "proxy_bypass", "proxy_listener"):
            self.assertEqual(result["extra." + key].status, Status.WARN)
        values = list(fixtures())
        values[2]["proxy"]["system"]["pac_configured"] = True
        self.assertEqual(evaluate(values)["extra.proxy_layers"].status, Status.UNKNOWN)

    def test_tls_certificate_failure_and_absence_are_not_passes(self):
        values = list(fixtures())
        values[3]["responses"][0]["tls_verified"] = False
        self.assertEqual(evaluate(values)["extra.tls"].status, Status.FAIL)
        values[3]["responses"] = []
        self.assertEqual(evaluate(values)["extra.tls"].status, Status.UNKNOWN)

    def test_clock_requires_agreeing_distinct_https_sources(self):
        for offsets in ((500, 503), (0, 300), (None, 3)):
            values = list(fixtures())
            for response, offset in zip(values[3]["responses"], offsets):
                response["clock_offset_seconds"] = offset
            status = evaluate(values)["extra.clock"].status
            self.assertEqual(status, Status.WARN if offsets == (500, 503) else Status.UNKNOWN)
        values = list(fixtures())
        values[3]["responses"][1]["endpoint"] = values[3]["responses"][0]["endpoint"]
        self.assertEqual(evaluate(values)["extra.clock"].status, Status.UNKNOWN)

    def test_storage_and_account_integrity_have_different_failure_severity(self):
        values = list(fixtures())
        values[2]["storage"]["free_bytes"] = 10
        values[2]["account"]["pending"] = ["A.previous"]
        result = evaluate(values)
        self.assertEqual(result["extra.storage"].status, Status.WARN)
        self.assertEqual(result["extra.account"].status, Status.WARN)
        values[2]["account"]["valid"] = False
        self.assertEqual(evaluate(values)["extra.account"].status, Status.FAIL)

    def test_unconfigured_optional_cli_is_skipped_not_failed(self):
        values = list(fixtures())
        values[2]["cli"] = {}
        result = evaluate(values)
        self.assertEqual(result["extra.cli_paths"].status, Status.SKIPPED)
        self.assertEqual(result["extra.cli_env"].status, Status.SKIPPED)
        values[2]["cli"] = {"api_key_present": True, "auth_token_present": True}
        self.assertEqual(evaluate(values)["extra.cli_env"].status, Status.WARN)


class LocalFactsTests(unittest.TestCase):
    def test_hosts_parser_ignores_unrelated_content_and_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            path.write_text("127.0.0.1 localhost private.local\n# 1.1.1.1 claude.ai\n8.8.8.8 CLAUDE.AI api.anthropic.com # comment\n")
            value = hosts_overrides(path)
            self.assertEqual(len(value["overrides"]), 2)
            self.assertNotIn("private.local", json.dumps(value))

    def test_bypass_detects_exact_suffix_and_wildcard_without_exporting_internal_hosts(self):
        for value in ("*.anthropic.com", ".anthropic.com", "api.anthropic.com:443", "*"):
            self.assertIn("api.anthropic.com", bypass_matches(value)["target_matches"])
        self.assertEqual(bypass_matches("notclaude.ai,private.company")["target_matches"], [])
        self.assertNotIn("private.company", json.dumps(bypass_matches("private.company")))

    def test_windows_proxy_values_are_sanitized_and_pac_not_fetched(self):
        raw = {"ProxyEnable": 1, "ProxyServer": "http=user:SECRET@127.0.0.1:7897", "AutoConfigURL": "https://secret.example/pac?token=SECRET", "ProxyOverride": "private.internal;*.anthropic.com"}
        value = read_system_proxy("Windows", lambda: raw)
        self.assertTrue(value["pac_configured"])
        self.assertEqual(value["endpoints"], ["http://127.0.0.1:7897"])
        self.assertNotIn("SECRET", json.dumps(value))
        self.assertNotIn("private.internal", json.dumps(value))

    def test_macos_proxy_parser_and_exception_list(self):
        text = "HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 7897\nProxyAutoDiscoveryEnable : 1\nExceptionsList : <array> {\n0 : *.anthropic.com\n}\n"
        value = read_system_proxy("Darwin", lambda: text)
        self.assertEqual(value["endpoints"], ["http://127.0.0.1:7897"])
        self.assertTrue(value["auto_detect"])
        self.assertEqual(value["bypass"]["target_matches"], ["api.anthropic.com"])

    def test_listener_connects_only_to_configured_loopback_without_port_scan(self):
        connector = Mock()
        connector.return_value.__enter__ = Mock()
        connector.return_value.__exit__ = Mock()
        values = probe_listeners([{"url": "http://127.0.0.1:7897"}, {"url": "http://8.8.8.8:443"}], connector)
        self.assertEqual(connector.call_count, 1)
        self.assertEqual(len(values), 1)

    def test_configuration_checks_do_not_export_mcp_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"mcpServers": {"sensitive-name": {"command": "example", "env": {"API_KEY": "SECRET"}}}}))
            value = config_shape(path)
            self.assertTrue(value["valid"])
            self.assertEqual(value["mcp_server_count"], 1)
            self.assertNotIn("SECRET", json.dumps(value))
            self.assertNotIn("sensitive-name", json.dumps(value))
            path.write_text("not-json")
            self.assertFalse(config_shape(path)["valid"])

    def test_cli_wrappers_are_deduplicated_and_values_never_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for name in ("claude", "claude.cmd"):
                (home / name).write_text("not executed")
            env = {"PATH": directory, "ANTHROPIC_API_KEY": "SECRET", "ANTHROPIC_AUTH_TOKEN": "OTHER_SECRET", "ANTHROPIC_BASE_URL": "https://user:password@example.com"}
            value = cli_facts(home, env)
            self.assertEqual(value["installation_count"], 1)
            self.assertFalse(value["endpoint_valid"])
            self.assertNotIn("SECRET", json.dumps(value))
            for endpoint in ("https://[bad", "https://example.com:bad", "ftp://example.com", "https://has space.example"):
                self.assertFalse(cli_facts(home, {"ANTHROPIC_BASE_URL": endpoint})["endpoint_valid"])

    def test_account_metadata_check_is_read_only_and_refuses_disagreement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            self.assertTrue(account_markers(state, root / "Claude")["valid"])
            self.assertFalse(state.exists())
            state.mkdir()
            (state / "current").write_text("A")
            (state / "current.txt").write_text("B")
            self.assertFalse(account_markers(state, root / "Claude")["valid"])

    def test_local_snapshot_keeps_only_whitelisted_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            hosts = home / "hosts"
            hosts.write_text("127.0.0.1 localhost\n")
            env = {"ANTHROPIC_API_KEY": "PRIVATE_VALUE", "HTTP_PROXY": "http://u:PRIVATE_VALUE@127.0.0.1:7897"}
            value = local_snapshot({}, home=home, environ=env, system="Windows", system_reader=lambda: {"ProxyEnable": 0, "AutoDetect": 0},
                                   listener=lambda proxies: [], hosts_path=hosts)
            self.assertNotIn("PRIVATE_VALUE", json.dumps(value))
            self.assertTrue(value["account"]["valid"])
            self.assertFalse((home / ".claude-switcher").exists())
            self.assertIn("free_bytes", value["storage"])


class RouteTests(unittest.TestCase):
    def test_dns_parser_filters_and_records_errors(self):
        values = [(socket.AF_INET, None, None, None, ("8.8.8.8", 0))] * 2
        self.assertEqual(resolve_host("fixture", lambda *a, **k: values)["addresses"], ["8.8.8.8"])
        self.assertEqual(resolve_host("fixture", Mock(side_effect=OSError()))["addresses"], [])

    def test_fixed_host_queries_and_family_samples(self):
        resolver = Mock(return_value=[(socket.AF_INET, None, None, None, ("8.8.8.8", 0)), (socket.AF_INET6, None, None, None, ("2001:4860:4860::8888", 0))])
        router = Mock(return_value=[])
        collect_facts(resolver, router)
        self.assertEqual({c.args[0] for c in resolver.call_args_list}, {"claude.ai", "api.anthropic.com"})
        self.assertEqual(router.call_args.args[0], ["8.8.8.8", "2001:4860:4860::8888"])

    def test_windows_route_command_is_read_only_and_ip_validated(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, stdout='[{"destination":"8.8.8.8","interface":"tun0","interface_index":8}]'))
        value = lookup_routes(["8.8.8.8"], "Windows", runner)
        self.assertEqual(value[0]["interface_index"], 8)
        command = runner.call_args.args[0]
        decoded = base64.b64decode(command[-1]).decode("utf-16le")
        self.assertIn("Find-NetRoute", decoded)
        self.assertNotIn("New-NetRoute", decoded)
        with self.assertRaises(ValueError):
            lookup_routes(["8.8.8.8; execute-something"], "Windows", runner)
        self.assertEqual(runner.call_count, 1)

    def test_macos_routes_and_unavailable_output(self):
        text = "route to: 8.8.8.8\n gateway: 198.18.0.1\n interface: utun3\n flags: <UP,DONE>\n"
        self.assertEqual(parse_mac_route(text, "8.8.8.8")["interface"], "utun3")
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=text))
        lookup_routes(["2001:4860:4860::8888"], "Darwin", runner)
        self.assertIn("-inet6", runner.call_args.args[0])
        self.assertIn("error", parse_mac_route("malformed", "8.8.8.8"))

    def test_worker_offline_and_hard_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "facts.private.json"
            with patch("envscope.network_facts.collect_facts", side_effect=AssertionError("must not resolve")):
                network_main(["--offline", str(file)])
            self.assertEqual(json.loads(file.read_text())["mode"], "offline")
        with patch("envscope.network_facts.subprocess.run", side_effect=subprocess.TimeoutExpired("worker", 16)):
            self.assertIn("error", bounded_facts())


class MeasurementIntegrationTests(unittest.TestCase):
    def test_audit_merges_fourteen_plus_eighteen_without_public_requests(self):
        inventory, network, local, _ = fixtures()
        transport = Mock()
        browser = Finding("browser.webrtc", "browser", Status.UNKNOWN, "fixture", "test")
        with patch("envscope.probes.collect", return_value=inventory), patch("envscope.probes.bounded_facts", return_value=network), \
                patch("envscope.probes.http_observations", return_value=[]), patch("envscope.probes.stun_observations", return_value=[]), \
                patch("envscope.probes.local_snapshot", return_value=local), patch("envscope.probes.assess_snapshot", return_value=browser), \
                patch("envscope.baseline.guard_state", return_value={"registered": False}), patch("envscope.baseline.runtime_rules", return_value={"status": "unknown", "reason": "fixture"}), \
                patch("envscope.baseline.extra_network", return_value=({}, [])), \
                patch('envscope.environment_info.device_information',return_value={'state':'completed','rows':[]}):
            findings = audit(Policy(), transport, online=True, stun=True, ipv6=True, baseline_config={})
        self.assertEqual(sum(f.id.startswith("baseline.") for f in findings), 14)
        self.assertEqual(sum(f.id.startswith("extra.") for f in findings), 18)
        self.assertEqual(len({f.id for f in findings}), len(findings))
        transport.get.assert_not_called()

    def test_disabled_registered_guard_is_not_running_pass(self):
        snapshot = {'rows': [{'id': 'guard', 'owned': True, 'present': True, 'registered': True, 'enabled': False, 'running': False}]}
        with patch("envscope.baseline.platform.system", return_value="Windows"), patch('envscope.process_guard.NativeGuardIO.legacy', return_value=snapshot), patch('envscope.process_guard.ProcessGuard.status', return_value={'state':'disabled'}):
            value = guard_state()
        self.assertTrue(value["registered"])
        self.assertFalse(value["enabled"])
        self.assertFalse(value["running"])
        with patch('envscope.process_guard.NativeGuardIO.legacy', side_effect=ValueError('fixture denied')):
            self.assertEqual(guard_state()["error"], "unavailable")

    def test_curl_metrics_certificate_and_clock_headers_are_selected_only(self):
        def runner(command, **kwargs):
            header = Path(command[command.index("--dump-header") + 1])
            header.write_bytes(("HTTP/1.1 200 OK\r\nDate: " + format_datetime(datetime.now(timezone.utc), usegmt=True) + "\r\nSet-Cookie: SECRET\r\n\r\n").encode("ascii"))
            return subprocess.CompletedProcess(command, 0, stdout='{}' + MARKER + '200|application/json|0.01|0.02|0.05|0.08|0.1|0|2')
        transport = CurlTransport(runner=runner)
        transport.executable = "fixture-curl"
        response = transport.get("https://example.org/")
        self.assertTrue(response.tls_verified)
        self.assertEqual(response.timings["tcp_ms"], 10)
        self.assertEqual(response.timings["tls_ms"], 30)
        self.assertLess(abs(response.clock_offset_seconds), 2)
        self.assertNotIn("SECRET", str(response))

    def test_invalid_timing_metadata_and_certificate_errors_never_pass(self):
        for fields in ('0|0|0|0|nan|0|2', '1|0|0|0|0|0|2'):
            runner = Mock(return_value=subprocess.CompletedProcess([], 0, stdout='{}' + MARKER + '200|application/json|' + fields))
            transport = CurlTransport(runner=runner)
            transport.executable = "fixture"
            response = transport.get("https://example.org")
            self.assertEqual(response.timings, {})
            self.assertIsNone(response.tls_verified)
        runner = Mock(return_value=subprocess.CompletedProcess([], 60, stdout=""))
        transport = CurlTransport(runner=runner)
        transport.executable = "fixture"
        self.assertFalse(transport.get("https://example.org").tls_verified)
