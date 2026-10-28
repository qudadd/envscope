from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler, Request
import unittest
from unittest.mock import patch

from envscope.inventory import macos_network, parse_macos_interfaces
from envscope.model import Finding, Status
from envscope.service import make_server
from envscope.accounts import AccountManager
from envscope.operations import Operations
from envscope.state import StateStore


def snapshot():
    return {"schema_version": 1, "kind": "envscope-browser-observations", "contains_sensitive": True,
            "created_at": datetime.now(timezone.utc).isoformat(), "ice_complete": True,
            "http": [{"source": "ipify-v4", "ip": "8.8.8.8", "family": 4},
                     {"source": "cloudflare-v4", "ip": "8.8.8.8", "family": 4}],
            "ice": [{"address": "8.8.8.8", "type": "srflx"}]}


def fixture_audit(*args, **kwargs):
    return [Finding("http.egress", "系统 HTTP IPv4", Status.UNKNOWN, "fixture without network", "test-fixture"),
            Finding("browser.webrtc", "WebRTC", Status.UNKNOWN, "fixture without network", "test-fixture")]


class DesktopAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = StateStore(memory=True)
        self.operations = Operations(self.store, self.directory.name, discoverer=lambda: [])
        self.server = make_server(auditor=fixture_audit, store=self.store, operations=self.operations)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.opener = build_opener(ProxyHandler({}))
        self.token = json.loads(self.opener.open(self.origin + "/api/session", timeout=2).read())["token"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.directory.cleanup()

    def post(self, value, token=None, origin=None, path="/api/audit"):
        headers = {"Content-Type": "application/json", "Origin": origin or self.origin,
                   "X-EnvScope-Token": self.token if token is None else token}
        return self.opener.open(Request(self.origin + path, data=json.dumps(value).encode(), headers=headers), timeout=3)

    def test_one_click_combines_browser_and_native_without_exporting_addresses(self):
        response = self.post({"snapshot": snapshot()})
        report = json.loads(response.read())
        self.assertEqual(report["mode"], "one-click-desktop")
        self.assertFalse(report["contains_sensitive"])
        self.assertIn("browser.http_v4", [f["id"] for f in report["findings"]])
        self.assertNotIn("8.8.8.8", json.dumps(report))

    def test_quit_refuses_to_interrupt_a_running_operation(self):
        self.server.audit_lock.acquire()
        try:
            with self.assertRaises(HTTPError) as caught:
                self.post({}, path="/api/quit")
            self.assertEqual(caught.exception.code, 409)
        finally:
            self.server.audit_lock.release()

    def test_selected_item_resolution_requires_current_evidence(self):
        for verified in (False, True):
            with self.subTest(verified=verified):
                self.server.solution_before = {"problems": [], "check": {"id":"guard","title":"进程守护","status":"unknown"}}
                self.server.auditor = lambda *a, **k: fixture_audit() + ([Finding("baseline.guard", "进程守护", Status.PASS, "fixture running task", "test-fixture")] if verified else [])
                value = json.loads(self.post({"snapshot": snapshot()}).read())
                self.assertEqual(value["resolution"]["item"]["state"], "verified" if verified else "unverified")
                self.assertNotEqual(value["decision"]["verdict"], "clear_in_scope")

    def test_forged_origin_and_missing_token_rejected(self):
        for options in ({"origin": "http://example.org"}, {"token": ""}):
            with self.assertRaises(HTTPError) as caught:
                self.post({"snapshot": snapshot()}, **options)
            self.assertEqual(caught.exception.code, 403)

    def test_api_does_not_accept_command_target_or_proxy(self):
        for key in ("command", "target", "proxy", "controller"):
            with self.assertRaises(HTTPError) as caught:
                self.post({"snapshot": snapshot(), key: "untrusted"})
            self.assertEqual(caught.exception.code, 400)

    def test_bad_timestamp_type_is_rejected_before_audit(self):
        value = snapshot()
        value["created_at"] = {}
        with self.assertRaises(HTTPError) as caught:
            self.post({"snapshot": value})
        self.assertEqual(caught.exception.code, 400)

    def test_concurrent_run_is_rejected(self):
        self.server.audit_lock.acquire()
        try:
            with self.assertRaises(HTTPError) as caught:
                self.post({"snapshot": snapshot()})
            self.assertEqual(caught.exception.code, 409)
        finally:
            self.server.audit_lock.release()

    def test_catalog_requires_token_and_is_read_only(self):
        request = Request(self.origin + "/api/catalog", headers={"X-EnvScope-Token": self.token})
        value = json.loads(self.opener.open(request).read())
        self.assertIn("install", [a["id"] for a in value["legacy"]["actions"]])
        self.assertIn("accounts", value)
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])
        with self.assertRaises(HTTPError):
            self.opener.open(self.origin + "/api/catalog")

    def test_actions_cannot_supply_report_executable_or_nonboolean_confirmation(self):
        for value in ({"action": "app-launch", "params": {}, "confirmed": "yes"},
                      {"action": "app-launch", "params": {}, "confirmed": True, "report": {}},
                      {"action": "account-switch", "params": {"slot": "B", "executable": "bad"}, "confirmed": True}):
            with self.assertRaises(HTTPError) as caught:
                self.post(value, path="/api/action")
            self.assertEqual(caught.exception.code, 400)
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])

    def test_each_switch_reruns_native_audit_and_cannot_use_old_pass(self):
        root = Path(self.directory.name)
        data = root / "Claude"
        data.mkdir()
        (data / "session.txt").write_text("synthetic")
        calls = []
        def auditor(*args, **kwargs):
            calls.append(kwargs)
            keys = ("http.egress", "udp.stun", "baseline.proxy", "baseline.tun", "baseline.ipv6", "baseline.guard", "baseline.rules")
            return [Finding(k, k, Status.PASS if len(calls) == 1 else Status.UNKNOWN, "fixture", "test") for k in keys]
        self.server.auditor = auditor
        stop = []
        self.operations.accounts = AccountManager(root / "state", data, stop_app=lambda: stop.append(True) or True, launch_app=lambda: True)
        self.post({"snapshot": snapshot()}).read()
        response = self.post({"action": "account-switch", "params": {"slot": "B"}, "confirmed": True}, path="/api/action")
        result = json.loads(response.read())
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(len(calls), 2)
        self.assertIn("baseline_config", calls[-1])
        self.assertEqual(stop, [])
        self.assertEqual((data / "session.txt").read_text(), "synthetic")
        self.assertIn("latest_report", result)

    def test_settings_and_history_use_server_owned_reports(self):
        response = self.post({"action": "settings-save", "params": {"country": "us"}, "confirmed": False}, path="/api/action")
        self.assertEqual(json.loads(response.read())["settings"]["country"], "US")
        current = json.loads(self.post({"snapshot": snapshot()}).read())
        result = json.loads(self.post({"action": "history-report", "params": {"id": current["report_id"]}, "confirmed": False}, path="/api/action").read())
        self.assertFalse(result["report"]["contains_sensitive"])
        self.assertEqual(len(self.store.history()), 1)

    def test_teaching_progress_cannot_change_policy_or_authorize_operations(self):
        previous = self.store.settings()
        value = json.loads(self.post({"action": "learning-complete", "params": {"version": 1}, "confirmed": False}, path="/api/action").read())
        self.assertTrue(value["learning"]["completed"])
        self.assertEqual(self.store.settings(), previous)
        self.assertIsNone(self.server.last_raw_report)
        for params in ({"version": True}, {"version": 1, "require_guard": False}, {"version": 1, "usage": "cli"}):
            with self.assertRaises(HTTPError) as caught:
                self.post({"action": "learning-complete", "params": params, "confirmed": False}, path="/api/action")
            self.assertEqual(caught.exception.code, 400)
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])


class MacInventoryTests(unittest.TestCase):
    def test_interface_parser_does_not_collect_mac_addresses(self):
        text = """en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 192.168.1.4 netmask 0xffffff00
\tinet6 fe80::1%en0 prefixlen 64
utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xffffffff
"""
        value = parse_macos_interfaces(text)
        self.assertEqual(len(value), 2)
        self.assertEqual(value[1]["name"], "utun2")
        self.assertNotIn("aa:bb", json.dumps(value))
        self.assertEqual(value[0]["addresses"][1]["family"], 6)

    def test_dns_and_route_collection_use_read_only_commands(self):
        def fake(command):
            if command[0] == "/sbin/ifconfig":
                return "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1\n"
            if command[0] == "/usr/sbin/scutil":
                return "resolver #1\n  nameserver[0] : 1.1.1.1\n"
            return "  gateway: 192.168.1.1\n  interface: en0\n"
        with patch("envscope.inventory.command_text", side_effect=fake):
            value = macos_network()
        self.assertEqual(value["dns"], ["1.1.1.1"])
        self.assertEqual(value["default_route"]["interface"], "en0")
