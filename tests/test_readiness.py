"""Desktop handoff uses synthetic evidence and injected process callbacks."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from envscope.accounts import PreflightError
from envscope.model import Finding, Status, make_report
from envscope.operations import Operations, launch_gate, quit_claude_gracefully
from envscope.policy import Policy
from envscope.readiness import launch_readiness
from envscope.state import StateStore


def ready_findings():
    rows = [Finding(key, key, Status.PASS, "fixture", "test-fixture") for key in
            ("http.egress", "udp.stun", "baseline.proxy", "baseline.tun", "baseline.ipv6", "baseline.guard", "baseline.rules")]
    return rows + [Finding("extra.desktop", "desktop", Status.PASS, "fixture", "test", [{"found": True}]),
                   Finding("extra.config", "config", Status.SKIPPED, "fixture", "test", [{"exists": False}, {"exists": True, "valid": False}]),
                   Finding("extra.account", "accounts", Status.PASS, "fixture", "test", [{"valid": True, "pending": [], "tracked": False}]),
                   Finding("baseline.reachability", "service", Status.PASS, "fixture", "test", [{"endpoint":"https://claude.ai/", "http_status":200, "tls_verified":True}]),
                   Finding("dns.leak", "DNS", Status.UNKNOWN, "unmeasured", "test")]


def ready_report():
    return make_report(ready_findings(), Policy(), "one-click-desktop")


class ReadinessTests(unittest.TestCase):
    def test_ready_checklist_does_not_claim_privacy_or_account_acceptance(self):
        report = ready_report()
        self.assertTrue(report["launch"]["ready"])
        self.assertTrue(launch_gate(report, {})[0])
        self.assertNotEqual(report["decision"]["verdict"], "clear_in_scope")
        self.assertIn("不证明账号权限", report["launch"]["scope"])

    def test_history_future_naive_stale_and_malformed_inputs_cannot_authorize_launch(self):
        for change in ({"mode": "imported"}, {"mode": "maintenance"},
                       {"created_at": (datetime.now(timezone.utc) - timedelta(seconds=91)).isoformat()},
                       {"created_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()},
                       {"created_at": datetime.now().isoformat()}, {"created_at": []}, {"findings": {}}):
            with self.subTest(change=change):
                self.assertFalse(launch_readiness({**ready_report(), **change})["ready"])
        self.assertFalse(launch_readiness(None)["ready"])

    def test_network_pass_does_not_replace_install_config_or_recovery_evidence(self):
        values = [("extra.desktop", {"found": None}), ("extra.desktop", {"found": 1}),
                  ("extra.config", {"exists": True, "valid": False}), ("extra.config", {"valid": True}),
                  ("extra.account", {"valid": True, "pending": ["Claude.previous"]}),
                  ("extra.account", {"valid": True, "pending": [], "tracked": True, "live_profile_present": False}),
                  ("extra.account", {"valid": None, "pending": []})]
        for key, value in values:
            report = ready_report()
            next(f for f in report["findings"] if f["id"] == key)["evidence"] = [value]
            with self.subTest(key=key, value=value):
                self.assertFalse(launch_gate(report, {})[0])
        report = ready_report()
        next(f for f in report["findings"] if f["id"] == "extra.config")["evidence"][0] = {"exists": True, "valid": True}
        self.assertTrue(launch_gate(report, {})[0], "unrelated invalid Code JSON is not a desktop launch requirement")

    def test_os_quit_requests_are_graceful_and_errors_never_mean_exited(self):
        with patch("envscope.operations.platform.system", return_value="Windows"), patch("envscope.operations._process", return_value=Mock(returncode=1)) as run:
            self.assertFalse(quit_claude_gracefully())
            command = run.call_args.args[0][-1]
            self.assertIn("CloseMainWindow", command)
            self.assertNotIn("Stop-Process", command)
        with patch("envscope.operations.platform.system", return_value="Darwin"), patch("envscope.operations._process", return_value=Mock(returncode=2)) as run:
            self.assertFalse(quit_claude_gracefully())
            self.assertEqual(run.call_count, 1)

    def test_desktop_service_needs_its_own_verified_response_and_keeps_access_challenges_explicit(self):
        for observation in ({"endpoint":"https://api.anthropic.com/v1/models", "http_status":401, "tls_verified":True},
                            {"endpoint":"https://claude.ai/", "http_status":200, "tls_verified":False},
                            {"endpoint":"https://claude.ai/", "http_status":200, "tls_verified":True, "error":"timeout"},
                            {"endpoint":"https://claude.ai/", "http_status":429, "tls_verified":True}):
            value = ready_report()
            next(f for f in value["findings"] if f["id"] == "baseline.reachability")["evidence"] = [observation]
            self.assertFalse(launch_readiness(value)["ready"])
        value = ready_report()
        next(f for f in value["findings"] if f["id"] == "baseline.reachability")["evidence"][0]["http_status"] = 403
        service = next(c for c in launch_readiness(value)["checks"] if c["id"] == "service")
        self.assertEqual(service["state"], "ready")
        self.assertIn("访问校验", service["reason"])

    def test_explicit_confirmation_fresh_preflight_and_fixed_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            launch, stop = Mock(return_value=True), Mock(return_value=True)
            operations = Operations(StateStore(memory=True), directory, discoverer=lambda: [], launcher=launch, restart_stopper=stop)
            for action in ("app-launch", "app-restart"):
                for confirmed in (False, 1, "yes"):
                    self.assertEqual(operations.run(action, {}, confirmed, ready_report())["state"], "confirmation_required")
                with self.assertRaises(PreflightError):
                    operations.run(action, {}, True, ready_report(), lambda: False)
                with self.assertRaises(ValueError):
                    operations.run(action, {"command": "anything"}, True, ready_report())
            launch.assert_not_called()
            stop.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])
            result = operations.run("app-launch", {}, True, ready_report(), lambda: True)
            self.assertEqual(result["state"], "started")
            self.assertFalse(result["profiles_changed"])
            launch.assert_called_once_with()
            stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
