"""Outcome-first guidance must not turn incomplete evidence into usability proof."""
import json
from pathlib import Path
import tempfile
import unittest

from envscope.guide import EXPLANATIONS, explain_check, usage_guide
from envscope.claude_checks import ITEMS
from envscope.state import StateStore


def report(usage="cli", code=401, tls=True, error="", problems=()):
    return {"usage": usage, "diagnosis": {"problems": list(problems)}, "findings": [
        {"id": "extra.cli_env", "evidence": [{"installation_count": 1}]},
        {"id": "extra.desktop", "evidence": [{"found": True}]},
        {"id": "extra.config", "evidence": [{"exists": False}, {"exists": True, "valid": True}]},
        {"id": "baseline.reachability", "evidence": [{"endpoint": "https://api.anthropic.com/v1/models", "http_status": code, "tls_verified": tls, "error": error}]},
    ]}


class UsageGuideTests(unittest.TestCase):
    def task(self, value, key):
        return next(t for t in usage_guide(value)["tasks"] if t["id"] == key)

    def test_anonymous_401_is_only_a_response_and_still_needs_manual_trial(self):
        value = usage_guide(report())
        self.assertEqual(value["tasks"][1]["state"], "responding")
        self.assertEqual(value["manual_confirmation"]["state"], "required")
        self.assertIn("权限", value["tasks"][1]["text"])
        self.assertEqual(value["next_action"], "try")

    def test_api_response_does_not_confirm_selected_desktop_or_both(self):
        for selected in ("desktop", "both", "auto"):
            self.assertEqual(self.task(report(selected), "connection")["state"], "unverified")
        both = report("both")
        both["findings"][-1]["evidence"].append({"endpoint": "https://claude.ai/", "http_status": 200, "tls_verified": True})
        self.assertEqual(self.task(both, "connection")["state"], "responding")

    def test_errors_unverified_tls_and_malformed_status_never_become_responding(self):
        for value in (report(code=403), report(code=429), report(code=500), report(code=True), report(tls=None), report(tls=False), report(error="timeout")):
            self.assertEqual(self.task(value, "connection")["state"], "unverified")
        value = report()
        for evidence in ([None, "bad"], [{"endpoint": "https://api.anthropic.com.evil/", "http_status": 200, "tls_verified": True}]):
            value["findings"][-1]["evidence"] = evidence
            self.assertEqual(self.task(value, "connection")["state"], "unverified")

    def test_absent_optional_config_is_valid_but_missing_evidence_is_unknown(self):
        self.assertEqual(self.task(report("both"), "setup")["state"], "checked")
        value = report()
        value["findings"][2]["evidence"] = []
        self.assertEqual(self.task(value, "setup")["state"], "unverified")
        self.assertEqual(self.task({"usage": "auto"}, "setup")["state"], "unverified")

    def test_protection_requirement_does_not_overwrite_connection_response(self):
        problem = {"id": "startup.tun", "title": "账号启动条件", "repair": None}
        value = report(problems=[problem])
        self.assertEqual(self.task(value, "connection")["state"], "responding")
        self.assertEqual(self.task(value, "protection")["state"], "attention")
        self.assertEqual(usage_guide(value)["primary_problem_id"], "startup.tun")

    def test_all_14_checks_have_plain_explanations_without_promoting_unknown(self):
        self.assertEqual(set(EXPLANATIONS), {item[0] for item in ITEMS})
        for key in EXPLANATIONS:
            text = explain_check(key, "unknown", False)
            self.assertTrue(text["why"] and text["next_step"])
            self.assertNotIn("已核实", text["result"])
        self.assertIn("能力有限", explain_check("dns", "unknown", False)["next_step"])
        self.assertIn("无需", explain_check("asn", "pass", False)["result"])


class LearningTests(unittest.TestCase):
    def test_completion_survives_new_origin_and_restart_without_policy_change(self):
        with tempfile.TemporaryDirectory() as root:
            store = StateStore(root)
            store.save_settings({"usage": "cli", "country": "US"})
            before = (Path(root) / "settings.private.json").read_bytes()
            self.assertFalse(store.learning()["completed"])
            store.complete_learning(1)
            restarted = StateStore(root)
            self.assertTrue(restarted.learning()["completed"])
            self.assertEqual(before, (Path(root) / "settings.private.json").read_bytes())
            self.assertEqual(restarted.settings()["usage"], "cli")

    def test_memory_mode_and_strict_version(self):
        store = StateStore(memory=True)
        for bad in (True, False, "1", None, 0, 2):
            with self.assertRaises(ValueError):
                store.complete_learning(bad)
        store.complete_learning(1)
        self.assertTrue(store.learning()["completed"])

    def test_malformed_or_old_learning_state_reopens_teaching(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "learning.private.json"
            for value in ([1], {"version": True, "completed": True}, {"version": 1, "completed": "yes"}, {"version": 0, "completed": True}):
                path.write_text(json.dumps(value), encoding="utf-8")
                self.assertFalse(StateStore(root).learning()["completed"])


if __name__ == "__main__":
    unittest.main()
