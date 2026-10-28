"""Practical feature tests: no installed profiles, processes or public network."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.accounts import AccountManager, PreflightError
from envscope.baseline import DOMAINS, collect_baseline, verify_rules
from envscope.discovery import discover_proxies, safe_local_proxy
from envscope.model import Finding, Status, make_report
from envscope.operations import Operations, launch_gate
from envscope.policy import Policy
from envscope.report import redact
from envscope.state import StateStore
from envscope.transport import CurlTransport, Response


def report(ip="8.8.8.8", status=Status.PASS):
    return make_report([Finding("http.egress", "IPv4", status, "fixture", "test", [{"ip": ip}])], Policy())


def gate_report():
    findings = [Finding(key, key, Status.PASS, "fixture", "test") for key in (
        "http.egress", "udp.stun", "baseline.proxy", "baseline.tun", "baseline.ipv6", "baseline.guard", "baseline.rules")]
    findings += [Finding("extra.desktop", "desktop", Status.PASS, "fixture", "test", [{"found": True}]),
                 Finding("extra.config", "config", Status.SKIPPED, "fixture", "test", [{"exists": False}]),
                 Finding("baseline.reachability", "service", Status.PASS, "fixture", "test", [{"endpoint":"https://claude.ai/", "http_status":200, "tls_verified":True}]),
                 Finding("extra.account", "accounts", Status.PASS, "fixture", "test", [{"valid": True, "pending": [], "tracked": False}])]
    findings.append(Finding('baseline.country','country','warn','fixture','fixture',[{'actual':'US'}]))
    return make_report(findings, Policy(), "one-click-desktop", {'usage_country':'US'})


class HistoryTests(unittest.TestCase):
    def test_reads_are_side_effect_free_and_settings_are_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "unused"
            store = StateStore(root)
            self.assertEqual(store.history(), [])
            self.assertEqual(store.settings()["client"], "auto")
            self.assertFalse(root.exists())
            for settings in ({"country": "USA"}, {"require_guard": "false"}, {"allowed_ipv6": ["8.8.8.8"]},
                             {"allowed_ipv4": [8]}, {"client": "anything"}, {"command": "x"}, {"webrtc_policy": "anything"}):
                with self.assertRaises(ValueError):
                    store.save_settings(settings)
            self.assertFalse(root.exists())

    def test_preferences_backup_restore_and_corrupt_preferences(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.save_settings({"country": "us", "allowed_ipv4": ["8.8.8.8/24"]})
            self.assertEqual(store.settings()["country"], "US")
            self.assertEqual(store.settings()["allowed_ipv4"], ["8.8.8.0/24"])
            store.restore_settings()
            self.assertEqual(store.settings()["country"], "")
            (Path(directory) / "settings.private.json").write_text('{"allowed_ipv4": [5]}')
            self.assertEqual(store.settings()["allowed_ipv4"], [])

    def test_history_private_hmac_survives_restart_and_does_not_export_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            first = report()
            self.assertIsNone(store.address_change(first["findings"]))
            store.record(first)
            store = StateStore(directory)
            self.assertIs(store.address_change(report()["findings"]), False)
            second = report("1.1.1.1", Status.WARN)
            self.assertIs(store.address_change(second["findings"]), True)
            store.record(second)
            delta = store.compare(first["report_id"], second["report_id"])
            self.assertIs(delta["observed_address_set_changed"], True)
            self.assertEqual(delta["changes"][0]["after"], "warn")
            for file in Path(directory).rglob("*.json"):
                text = file.read_text(encoding="utf-8")
                self.assertNotIn("8.8.8.8", text)
                self.assertNotIn("1.1.1.1", text)
            self.assertFalse(store.report(second["report_id"])["contains_sensitive"])

    def test_failed_observation_does_not_mean_address_changed(self):
        store = StateStore(memory=True)
        first = report()
        store.record(first)
        absent = report("not-an-ip", Status.UNKNOWN)
        self.assertIsNone(store.address_change(absent["findings"]))
        store.record(absent)
        self.assertIsNone(store.compare(first["report_id"], absent["report_id"])["observed_address_set_changed"])

    def test_missing_comparison_key_does_not_falsely_report_ip_change(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.record(report())
            (Path(directory) / "history-key.private.json").unlink()
            restarted = StateStore(directory)
            self.assertIsNone(restarted.address_change(report()["findings"]))

    def test_history_is_bounded_and_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            for _ in range(53):
                store.record(report())
            self.assertEqual(len(store.history()), 50)
            self.assertEqual(len(list((Path(directory) / "history").glob("*.json"))), 50)
            with self.assertRaises(ValueError):
                store.report("../settings.private.json")


class DiscoveryTests(unittest.TestCase):
    def test_never_autoselects_remote_named_or_credentialed_proxies(self):
        for value in ("http://example.org:80", "http://localhost:7890", "http://u:p@127.0.0.1:7890", "http://127.0.0.1:0", "http://127.0.0.1:80/x", "http://127.0.0.1:80\n"):
            self.assertIsNone(safe_local_proxy(value))
        self.assertEqual(safe_local_proxy("socks5://[::1]:7891"), "socks5://[::1]:7891")

    def test_environment_registry_and_file_are_deduplicated_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev"
            config.mkdir(parents=True)
            (config / "clash-verge.yaml").write_text("mixed-port: 7897\nsocks-port: 7898\nsecret: DO_NOT_EXPOSE\n")
            proxies = discover_proxies(directory, "Windows", {"HTTP_PROXY": "http://127.0.0.1:7897"},
                                       system_reader=lambda: "http=127.0.0.1:7897;https=127.0.0.1:7897")
            self.assertEqual(len(proxies), 2)
            self.assertEqual(len(proxies[0]["sources"]), 4)
            self.assertNotIn("DO_NOT_EXPOSE", json.dumps(proxies))
            self.assertFalse(proxies[0]["connection_verified"])

    def test_macos_proxy_parser_respects_enabled_flag(self):
        data = "HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 7897\nSOCKSEnable : 0\nSOCKSProxy : 127.0.0.1\nSOCKSPort : 7898\n"
        with tempfile.TemporaryDirectory() as directory:
            values = discover_proxies(directory, "Darwin", {}, system_reader=lambda: data)
        self.assertEqual([v["url"] for v in values], ["http://127.0.0.1:7897"])


def runtime():
    entries = [{"type": "AND", "payload": "((NETWORK,UDP),(DST-PORT," + str(p) + "))", "proxy": "group"} for p in (3478, 5349, 19302)]
    entries += [{"type": "DomainSuffix", "payload": domain, "proxy": "group"} for domain in DOMAINS]
    return {"mode": "rule"}, {"rules": entries}, {"proxies": {"group": {"all": ["node"], "now": "node"}, "node": {"type": "Shadowsocks", "udp": True}}}


class BaselineTests(unittest.TestCase):
    def test_rules_validate_order_target_disabled_group_and_udp(self):
        config, rules, proxies = runtime()
        self.assertEqual(verify_rules(config, rules, proxies, {})["status"], "pass")
        for mutation in (lambda r: r["rules"].reverse(), lambda r: r["rules"][4].update(proxy="DIRECT"),
                         lambda r: r["rules"][1].update(extra={"disabled": True}), lambda r: r["rules"][0].update(payload="3478")):
            altered = deepcopy(rules)
            mutation(altered)
            self.assertNotEqual(verify_rules(config, altered, proxies, {"proxy_group": "group"})["status"], "pass")
        proxies["proxies"]["node"]["udp"] = False
        self.assertEqual(verify_rules(config, rules, proxies, {})["status"], "warn")
        proxies["proxies"]["group"]["now"] = "group"
        self.assertEqual(verify_rules(config, rules, proxies, {})["status"], "warn")

    def test_direct_global_and_reject_are_distinguished(self):
        config, rules, proxies = runtime()
        self.assertEqual(verify_rules({"mode": "direct"}, rules, proxies, {})["status"], "fail")
        self.assertNotEqual(verify_rules({"mode": "global"}, rules, proxies, {})["status"], "pass")
        for r in rules["rules"][:3]:
            r["proxy"] = "REJECT"
        proxies["proxies"]["node"]["udp"] = False
        self.assertEqual(verify_rules(config, rules, proxies, {"webrtc_policy": "reject"})["status"], "pass")

    def test_all_fourteen_categories_preserve_unknowns_and_metadata_scope(self):
        browser = Finding("browser.webrtc", "WebRTC", Status.UNKNOWN, "no public candidate", "fixture")
        inventory = {"locale": "en_US", "network": {"dns": ["1.1.1.1"], "known_clients": ["mihomo"],
                    "adapters": [{"InterfaceDescription": "Wintun", "Status": "Up"}], "ipv6_bindings": [{"Enabled": False}]}}
        with patch("envscope.baseline.guard_state", return_value={"registered": False}):
            findings = collect_baseline(inventory, [], [], browser, browser, {}, Mock(), online=False)
        self.assertEqual(len(findings), 14)
        by_id = {f.id: f for f in findings}
        self.assertEqual(by_id["baseline.webrtc"].status, Status.UNKNOWN)
        self.assertEqual(by_id["baseline.language"].status, Status.UNKNOWN)
        self.assertEqual(by_id["baseline.ipv6"].status, Status.PASS)
        self.assertEqual(by_id["baseline.reachability"].status, Status.UNKNOWN)
        self.assertEqual(by_id["baseline.dns"].status, Status.PASS)
        self.assertIn("配置存在不证明无泄漏", by_id["baseline.dns"].limitations[0])


class OperationTests(unittest.TestCase):
    def test_launch_gate_refuses_stale_failed_and_missing_evidence(self):
        value = gate_report()
        self.assertTrue(launch_gate(value, {})[0])
        value["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        self.assertFalse(launch_gate(value, {})[0])
        value = gate_report()
        value["findings"][1]["status"] = "unknown"
        self.assertFalse(launch_gate(value, {})[0])
        value = gate_report()
        value["findings"].append(Finding("browser.webrtc", "browser", Status.FAIL, "fixture", "test").to_dict())
        self.assertFalse(launch_gate(value, {})[0])

    def test_fresh_preflight_and_confirmation_protect_account_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "Claude"
            data.mkdir()
            (data / "keep.txt").write_text("unchanged")
            stop = Mock(return_value=True)
            accounts = AccountManager(root / ".claude-switcher", data, stop_app=stop, launch_app=lambda: True)
            operations = Operations(StateStore(memory=True), root, account_manager=accounts, discoverer=lambda: [])
            self.assertEqual(operations.run("account-switch", {"slot": "B"})["state"], "confirmation_required")
            self.assertEqual(operations.run("account-switch", {"slot": "B"}, confirmed=1)["state"], "confirmation_required")
            with self.assertRaises(PreflightError):
                operations.run("account-switch", {"slot": "B"}, True, report=gate_report(), preflight=lambda: False)
            stop.assert_not_called()
            self.assertEqual((data / "keep.txt").read_text(), "unchanged")

    def test_proxy_diagnostics_never_turn_denied_into_available(self):
        with tempfile.TemporaryDirectory() as directory:
            operations = Operations(StateStore(memory=True), directory, discoverer=lambda: [])
            fake = Mock()
            fake.proxy = "http://127.0.0.1:7897"
            fake.get.side_effect = [Response(403), Response(429)]
            with patch("envscope.operations.CurlTransport", return_value=fake):
                result = operations.run("proxy-diagnose", {"proxy": fake.proxy})
            self.assertEqual([o["access"] for o in result["evidence"]], ["access_denied", "rate_limited"])
            self.assertEqual(fake.get.call_count, 2)
            with self.assertRaises(ValueError):
                operations.run("proxy-diagnose", {"proxy": fake.proxy, "command": "anything"})

    def test_redaction_removes_home_name_and_proxy_credentials(self):
        safe = redact({"path": r"C:\Users\RealPerson\.local\x", "other": "/Users/person/.claude", "secret": "bad",
                       "proxy": "https://user:password@example.org:443?api_key=bad"})
        self.assertNotIn("RealPerson", json.dumps(safe))
        self.assertNotIn("/Users/person", json.dumps(safe))
        self.assertNotIn("user:password", json.dumps(safe))

    def test_bad_proxy_types_are_input_errors(self):
        for value in ([], {}, "http://127.0.0.1"):
            with self.assertRaises(ValueError):
                CurlTransport(value)
