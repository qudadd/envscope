from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from envscope.browser import assess_snapshot, load_snapshot
from envscope.model import Finding, Status, make_report
from envscope.policy import Policy, assess_addresses, assess_http, decide, normalize_ip
from envscope.switcher import import_text


def observation(ip="8.8.8.8", source="a"):
    return {"ip": ip, "source": source}


class PolicyTests(unittest.TestCase):
    def test_no_response_is_unknown_and_blocks_required_gate(self):
        f = assess_addresses("udp.stun", "UDP", [{"error": "timeout"}], Policy())
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertEqual(decide([f], ("udp.stun",))["verdict"], "incomplete")

    def test_missing_check_cannot_pass(self):
        self.assertEqual(decide([], ("dns.leak",))["verdict"], "incomplete")

    def test_ipv6_timeout_never_means_safe(self):
        self.assertEqual(assess_http([], Policy(), 6).status, Status.UNKNOWN)

    def test_single_ip_provider_is_partial(self):
        self.assertEqual(assess_http([observation()], Policy()).status, Status.WARN)

    def test_two_independent_http_providers_can_establish_consistency(self):
        f = assess_http([observation(source="a"), observation(source="b")], Policy())
        self.assertEqual(f.status, Status.PASS)

    def test_multi_exit_is_review_without_explicit_policy(self):
        f = assess_http([observation(source="a"), observation("1.1.1.1", "b")], Policy())
        self.assertEqual(f.status, Status.WARN)

    def test_ip_difference_is_not_automatically_real_ip_leak(self):
        f = assess_addresses("udp.stun", "UDP", [observation("1.1.1.1")], Policy(), ["8.8.8.8"])
        self.assertEqual(f.status, Status.WARN)

    def test_explicit_allowlist_violation_is_failure_even_if_partial(self):
        import ipaddress
        policy = Policy(allowed_ipv4=(ipaddress.ip_network("8.8.8.8/32"),))
        f = assess_addresses("udp.stun", "UDP", [observation("1.1.1.1")], policy)
        self.assertEqual(f.status, Status.FAIL)

    def test_address_families_are_not_substituted(self):
        self.assertEqual(assess_http([observation("2001:4860::1")], Policy(), 4).status, Status.UNKNOWN)
        f = assess_addresses("udp.stun", "UDP", [observation("2001:4860::1")], Policy(), ["8.8.8.8"])
        self.assertEqual(f.status, Status.WARN)

    def test_mapped_ipv6_canonicalizes_to_ipv4(self):
        self.assertEqual(str(normalize_ip("::ffff:8.8.8.8")), "8.8.8.8")

    def test_duplicate_required_or_typo_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "policy.json"
            for checks in ([], ["http.egres"], ["http.egress", "http.egress"]):
                file.write_text(json.dumps({"required_checks": checks}))
                with self.assertRaises(ValueError):
                    Policy.load(file)

    def test_imported_upstream_ok_is_not_a_pass(self):
        imported = import_text("WebRTC=ok:UDP不出网,零暴露\nDNS=fail:未走隧道\n")
        self.assertEqual([f.status for f in imported], [Status.UNKNOWN, Status.WARN])
        self.assertEqual(make_report(imported, Policy())["decision"]["verdict"], "incomplete")


class BrowserSnapshotTests(unittest.TestCase):
    def snapshot(self):
        return {"schema_version": 1, "kind": "envscope-browser-observations", "contains_sensitive": True,
                "created_at": datetime.now(timezone.utc).isoformat(), "ice_complete": True,
                "http": [{"ip": "8.8.8.8", "source": "ipify-v4"}, {"ip": "8.8.8.8", "source": "cloudflare-v4"}],
                "ice": [{"address": "8.8.8.8", "type": "srflx"}]}

    def test_valid_same_context_comparison(self):
        self.assertEqual(assess_snapshot(self.snapshot(), Policy()).status, Status.PASS)

    def test_missing_public_candidates_is_unknown(self):
        for candidate in ({"address": "host.local", "type": "host"}, {"address": "8.8.8.8", "type": "relay"}):
            snapshot = self.snapshot()
            snapshot["ice"] = [candidate]
            self.assertEqual(assess_snapshot(snapshot, Policy()).status, Status.UNKNOWN)

    def test_stale_and_future_cannot_pass(self):
        for offset in (-301, 60):
            snapshot = self.snapshot()
            snapshot["created_at"] = (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()
            self.assertEqual(assess_snapshot(snapshot, Policy()).status, Status.UNKNOWN)

    def test_redacted_and_incomplete_cannot_pass(self):
        for key in ("contains_sensitive", "ice_complete"):
            snapshot = self.snapshot()
            snapshot[key] = False
            self.assertEqual(assess_snapshot(snapshot, Policy()).status, Status.UNKNOWN)

    def test_one_baseline_source_is_review(self):
        snapshot = self.snapshot()
        snapshot["http"].pop()
        self.assertEqual(assess_snapshot(snapshot, Policy()).status, Status.WARN)

    def test_reported_verdict_is_ignored(self):
        snapshot = self.snapshot()
        snapshot.update(verdict="pass", ice=[], findings=[{"status": "pass"}])
        self.assertEqual(assess_snapshot(snapshot, Policy()).status, Status.UNKNOWN)

    def test_invalid_snapshot_arrays_rejected(self):
        snapshot = self.snapshot()
        snapshot["ice"] = ["malformed"]
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "browser.json"
            file.write_text(json.dumps(snapshot))
            with self.assertRaises(ValueError):
                load_snapshot(file)
