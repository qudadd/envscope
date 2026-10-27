"""Contract tests with fake runners; never execute upstream maintenance code."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from envscope.legacy import LegacyBridge, UPSTREAM_COMMIT, VENDOR_MANIFEST_SHA256


VENDOR = Path(__file__).resolve().parents[1] / "envscope" / "vendor" / "claude_switcher"


class FakeRunner:
    def __init__(self, stdout="OK:fixture", code=0, stderr=""):
        self.stdout, self.code, self.stderr = stdout, code, stderr
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, self.code, self.stdout, self.stderr)


class LegacyBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "用户 home"
        self.home.mkdir()
        self.runner = FakeRunner()

    def bridge(self, system="Darwin", installed=True, runner=None):
        bridge = LegacyBridge(platform_name=system, home=self.home, runner=runner or self.runner)
        if installed:
            bridge.core.parent.mkdir(parents=True, exist_ok=True)
            source = VENDOR / ("windows/claude-switch.ps1" if system == "Windows" else "core/claude-switch.sh")
            bridge.core.write_bytes(source.read_bytes())
        return bridge

    def snapshot(self, account="A"):
        source = self.home / ".claude-switcher" / "accounts" / account
        source.mkdir(parents=True)
        (source / "fixture.txt").write_text("fake account, no real credentials")
        return source

    def test_catalog_and_planner_without_install_do_not_create_legacy_state(self):
        bridge = self.bridge(installed=False)
        before = sorted(p.relative_to(self.home).as_posix() for p in self.home.rglob("*"))
        catalog = bridge.capabilities()
        self.assertFalse(catalog["backend"]["installed"])
        self.assertTrue(catalog["vendor"]["verified"])
        self.assertEqual(bridge.plan("status")["state"], "unavailable")
        self.assertEqual(bridge.plan("install")["state"], "planned")
        self.assertEqual(before, sorted(p.relative_to(self.home).as_posix() for p in self.home.rglob("*")))
        self.assertFalse((self.home / ".claude-switcher").exists())
        self.assertEqual(self.runner.calls, [])

    def test_vendor_has_complete_canonical_hash_manifest_and_license(self):
        self.assertEqual(hashlib.sha256((VENDOR / "VENDOR_MANIFEST.json").read_bytes()).hexdigest(), VENDOR_MANIFEST_SHA256)
        manifest = json.loads((VENDOR / "VENDOR_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["commit"], UPSTREAM_COMMIT)
        self.assertEqual(manifest["license"], "MIT")
        self.assertEqual(len(manifest["files"]), 57)
        for relative, metadata in manifest["files"].items():
            data = (VENDOR / relative).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), metadata["sha256"], relative)
            self.assertEqual(len(data), metadata["size"], relative)
        self.assertIn("Claude Switcher Contributors", (VENDOR / "LICENSE").read_text())
        self.assertFalse((VENDOR / ".git").exists())
        for line in (VENDOR / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            expected, relative = line.split(None, 1)
            self.assertEqual(hashlib.sha256((VENDOR / relative).read_bytes()).hexdigest(), expected)
        for name in ("install.ps1", "claude-switch.ps1", "claude-bodyguard.ps1", "SwitcherUI.ps1"):
            self.assertTrue((VENDOR / "windows" / name).read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r\n", (VENDOR / "core/claude-switch.sh").read_bytes())

    def test_corrupt_vendor_blocks_installer_without_runner(self):
        damaged = Path(self.temp.name) / "damaged"
        shutil.copytree(VENDOR, damaged)
        (damaged / "windows/install.ps1").write_text("tampered")
        bridge = LegacyBridge("Windows", self.home, damaged, self.runner)
        self.assertFalse(bridge.capabilities()["vendor"]["verified"])
        self.assertEqual(bridge.run("install", confirmed=True)["state"], "unavailable")
        self.assertEqual(self.runner.calls, [])

    def test_source_and_manifest_tampering_together_cannot_redefine_the_pin(self):
        damaged = Path(self.temp.name) / "manifest-tampered"
        shutil.copytree(VENDOR, damaged)
        file = damaged / "windows/install.ps1"
        file.write_bytes(b"tampered")
        manifest_path = damaged / "VENDOR_MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["windows/install.ps1"].update(sha256=hashlib.sha256(file.read_bytes()).hexdigest(), size=file.stat().st_size)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        bridge = LegacyBridge("Windows", self.home, damaged, self.runner)
        self.assertEqual(bridge.plan("install")["reason"], "vendor_manifest_integrity_failed")
        self.assertEqual(self.runner.calls, [])

    def test_installed_core_alias_into_envscope_is_not_an_update_target(self):
        bridge = self.bridge()
        with patch.object(type(bridge.core), "resolve", return_value=VENDOR / "core/claude-switch.sh"):
            self.assertEqual(bridge.plan("update-apply")["state"], "unavailable")
        self.assertEqual(self.runner.calls, [])

    def test_platform_matrix_uses_actual_native_commands(self):
        for system, check, update in (("Darwin", "update-check", "update"), ("Windows", "check-update", "update-now")):
            with self.subTest(system=system):
                bridge = self.bridge(system)
                self.assertEqual(bridge.plan("update-check")["argv"][-1], check)
                plan = bridge.plan("update-apply")
                self.assertEqual(plan["argv"][-1], update)
                self.assertFalse(plan["updates_envscope"])
                self.assertIn(str(bridge.core), plan["argv"])
                self.assertNotIn(str(VENDOR / "core/claude-switch.sh"), plan["argv"])
        windows = self.bridge("Windows")
        for action in ("check", "set-client", "set-region", "fingerprint", "cli-info", "open-safe", "snapshot-import"):
            # Parameterized commands need valid input before native support is
            # evaluated; catalog support is independently available without it.
            entry = next(item for item in windows.capabilities()["actions"] if item["id"] == action)
            self.assertFalse(entry["supported"], action)
        self.assertEqual(windows.plan("uninstall")["state"], "unsupported")

    def test_linux_catalog_cannot_plan_native_actions(self):
        bridge = self.bridge("Linux", installed=False)
        self.assertEqual(bridge.plan("install")["state"], "unsupported")
        self.assertEqual(bridge.run("status", confirmed=True)["state"], "unsupported")
        self.assertEqual(self.runner.calls, [])

    def test_installed_old_core_cannot_use_unsupported_read_only_update_entry(self):
        bridge = self.bridge()
        bridge.core.write_text('case "${1:-}" in\n    update) self_update "${2:-}" ;;\nesac\n')
        self.assertEqual(bridge.plan("update-check")["state"], "unavailable")
        self.assertEqual(bridge.run("update-check", confirmed=True)["state"], "unavailable")
        self.assertEqual(self.runner.calls, [])

    def test_sensitive_actions_require_actual_boolean_confirmation(self):
        bridge = self.bridge()
        for confirmed in (False, None, "true", 1):
            result = bridge.run("fix", confirmed=confirmed)
            self.assertEqual(result["state"], "blocked")
            self.assertEqual(result["reason"], "explicit_confirmation_required")
        self.assertEqual(self.runner.calls, [])
        result = bridge.run("fix", confirmed=True)
        self.assertEqual(result["state"], "completed")
        self.assertFalse(result["verified_by_envscope"])
        self.assertEqual(len(self.runner.calls), 1)

    def test_windows_update_check_can_run_without_writing_discovery_state(self):
        runner = FakeRunner("STATUS=latest\nCURRENT=1.0\nLATEST=1.0")
        bridge = self.bridge("Windows", runner=runner)
        result = bridge.run("update-check")
        self.assertEqual(result["state"], "completed")
        self.assertFalse((self.home / ".claude-switcher/accounts").exists())
        self.assertEqual(runner.calls[0][0][-1], "check-update")

    def test_legacy_switch_is_always_rejected(self):
        for system in ("Windows", "Darwin"):
            bridge = self.bridge(system)
            for target in ("A", "B", "../outside", "A; start calc"):
                result = bridge.run("switch", {"account": target}, confirmed=True, preflight=lambda: True)
                self.assertEqual(result["state"], "rejected")
                self.assertEqual(result["reason"], "managed_by_envscope_accounts")
        self.assertEqual(self.runner.calls, [])

    def test_api_cannot_choose_executable_core_shell_or_arbitrary_arguments(self):
        bridge = self.bridge()
        for key in ("argv", "args", "command", "core", "executable", "path", "script", "env", "timeout"):
            self.assertEqual(bridge.run("status", {key: "anything"}, confirmed=True)["state"], "rejected", key)
        for action in ("shell", "guard", "watchdog", "write-merge-rules", "clash-rules", "/bin/sh", None):
            self.assertEqual(bridge.run(action, confirmed=True)["state"], "rejected")
        self.assertEqual(self.runner.calls, [])

    def test_safe_browser_requires_a_fresh_callable_gate_each_run(self):
        bridge = self.bridge()
        params = {"url": "https://example.org/path?x=1&y=$value"}
        for gate in (None, True, {"verdict": "clear_in_scope"}, lambda: False, lambda: "true"):
            result = bridge.run("open-safe", params, confirmed=True, preflight=gate)
            self.assertEqual(result["state"], "blocked")
        gates = []
        for _ in range(2):
            result = bridge.run("open-safe", params, confirmed=True, preflight=lambda: gates.append(True) or True)
            self.assertEqual(result["state"], "completed")
        self.assertEqual(len(gates), 2)
        self.assertEqual(self.runner.calls[0][0][-2:], ["open-safe", params["url"]])

    def test_safe_browser_rejects_unsafe_schemes_credentials_and_control_characters(self):
        bridge = self.bridge()
        for url in ("file:///etc/passwd", "javascript:alert(1)", "https://u:p@example.org/", "https://example.org/\narg", "--flag", "https://example.org:99999"):
            self.assertEqual(bridge.plan("open-safe", {"url": url})["state"], "rejected", url)

    def test_clients_and_webrtc_policy_are_closed_enumerations(self):
        bridge = self.bridge()
        for client in ("clash-verge", "shadowrocket", "sing-box", "clashx", "surge", "auto"):
            self.assertEqual(bridge.plan("set-client", {"client": client})["argv"][-1], client)
        for client in ("wireguard", "surge; rm x", "../clash", ""):
            self.assertEqual(bridge.plan("set-client", {"client": client})["state"], "rejected")
        self.assertEqual(bridge.plan("fix", {"webrtc_policy": "reject"})["state"], "planned")
        self.assertEqual(bridge.plan("fix", {"webrtc_policy": "anything"})["state"], "rejected")
        self.assertEqual(self.bridge("Windows").plan("fix", {"webrtc_policy": "reject"})["state"], "rejected")

    def test_snapshots_use_password_stdin_and_never_expose_secret_in_plan_or_output(self):
        self.snapshot("A")
        password = "highly-private-password"
        target = Path(self.temp.name) / "snapshot.dmg"
        params = {"account": "A", "file": str(target), "password": password}
        runner = FakeRunner("OK:created " + str(target) + " password=" + password)
        bridge = self.bridge(runner=runner)
        plan = bridge.plan("snapshot-export", params)
        self.assertEqual(plan["argv"][-4:], ["snapshot-export", "A", str(target), "--password-stdin"])
        self.assertNotIn(password, json.dumps(plan))
        result = bridge.run("snapshot-export", params, confirmed=True)
        argv, kwargs = runner.calls[0]
        self.assertNotIn(password, " ".join(argv))
        self.assertEqual(kwargs["input"], password + "\n")
        self.assertNotIn(password, json.dumps(result))
        self.assertNotIn(str(target), json.dumps(result))
        self.assertEqual(result["state"], "completed")

    def test_snapshot_import_arguments_follow_original_contract(self):
        image = Path(self.temp.name) / "fake.dmg"
        image.write_bytes(b"fixture, not a real image")
        bridge = self.bridge()
        params = {"account": "D", "file": str(image), "password": "private"}
        self.assertEqual(bridge.plan("snapshot-import", params)["argv"][-4:],
                         ["snapshot-import", str(image), "D", "--password-stdin"])
        self.assertEqual(bridge.run("snapshot-import", params, confirmed=True)["state"], "completed")
        self.assertEqual(self.runner.calls[0][1]["input"], "private\n")
        self.assertFalse((self.home / ".claude-switcher/accounts").exists())

    def test_snapshot_password_missing_control_newline_and_short_export_are_rejected(self):
        self.snapshot("B")
        bridge = self.bridge()
        params = {"account": "B", "file": str(Path(self.temp.name) / "out.dmg")}
        self.assertEqual(bridge.plan("snapshot-export", params)["state"], "planned")
        self.assertEqual(bridge.run("snapshot-export", params, confirmed=True)["state"], "blocked")
        for password in ("short", "long-enough\nsecond-line", "long-enough\0", 123):
            self.assertEqual(bridge.plan("snapshot-export", {**params, "password": password})["state"], "rejected")
        self.assertEqual(self.runner.calls, [])

    def test_snapshot_slots_paths_active_account_and_overwrites_are_rejected(self):
        self.snapshot("C")
        bridge = self.bridge()
        target = Path(self.temp.name) / "out.dmg"
        base = {"account": "C", "file": str(target), "password": "private-long"}
        for account in ("E", "../C", "C/../../outside", "C; open app"):
            self.assertEqual(bridge.plan("snapshot-export", {**base, "account": account})["state"], "rejected")
        self.assertEqual(bridge.plan("snapshot-export", {**base, "file": "relative.dmg"})["state"], "rejected")
        (self.home / ".claude-switcher/current").write_text("C")
        self.assertEqual(bridge.plan("snapshot-export", base)["reason"], "cannot_export_active_account")
        (self.home / ".claude-switcher/current").write_text("A")
        target.write_bytes(b"do not overwrite")
        self.assertEqual(bridge.plan("snapshot-export", base)["state"], "rejected")
        self.assertEqual(bridge.plan("snapshot-import", base)["reason"], "account_slot_not_empty")

    def test_proxy_credentials_are_env_only_and_inherited_test_bypasses_are_removed(self):
        proxy = "socks5h://test-user:private-password@proxy.example:18080"
        runner = FakeRunner("OK:proxy " + proxy + " private-password test-user 8.8.8.8 2001:4860:4860::8888")
        bridge = self.bridge(runner=runner)
        with patch.dict(os.environ, {"CLAUDE_SWITCHER_SKIP_NET_CHECK": "1", "CLAUDE_SWITCHER_CHROME": "/malicious/browser", "WEBRTC_POLICY": "reject"}):
            plan = bridge.plan("diagnose-proxy", {"proxy": proxy})
            result = bridge.run("diagnose-proxy", {"proxy": proxy})
        self.assertNotIn(proxy, json.dumps(plan))
        argv, kwargs = runner.calls[0]
        self.assertEqual(argv[-1], "diagnose-proxy")
        self.assertEqual(kwargs["env"]["CLAUDE_SWITCHER_PROXY_URL"], proxy)
        self.assertNotIn("CLAUDE_SWITCHER_SKIP_NET_CHECK", kwargs["env"])
        self.assertNotIn("CLAUDE_SWITCHER_CHROME", kwargs["env"])
        self.assertNotIn("WEBRTC_POLICY", kwargs["env"])
        for private in (proxy, "private-password", "test-user", "8.8.8.8", "2001:4860:4860::8888"):
            self.assertNotIn(private, json.dumps(result))

    def test_invalid_proxy_never_falls_back_to_another_path(self):
        bridge = self.bridge()
        for value in ("", "http://localhost", "socks5://localhost:0", "http://localhost:1/path", "http://localhost:1?token=secret", None):
            self.assertEqual(bridge.run("diagnose-proxy", {"proxy": value})["state"], "rejected")
        self.assertEqual(self.runner.calls, [])

    def test_original_set_client_targets_installed_core_not_vendor_source(self):
        bridge = self.bridge()
        result = bridge.run("set-client", {"client": "surge"}, confirmed=True)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(self.runner.calls[0][1]["env"]["CLAUDE_SWITCHER_CORE"], str(bridge.core))

    def test_installers_start_interactive_flow_and_do_not_claim_installation_completed(self):
        for system, mode in (("Darwin", "macos_terminal_interactive"), ("Windows", "windows_elevated_interactive")):
            runner = FakeRunner(stdout="")
            bridge = self.bridge(system, installed=False, runner=runner)
            self.assertEqual(bridge.run("install")["state"], "blocked")
            result = bridge.run("install", confirmed=True)
            self.assertEqual(result["state"], "started")
            self.assertIn("not_observed", result["reason"])
            argv, kwargs = runner.calls[0]
            self.assertEqual(kwargs["launch_mode"], mode)
            self.assertNotIn("-Command", argv)
            self.assertNotIn("-EncodedCommand", argv)
            self.assertTrue(argv[-1].endswith("install.ps1" if system == "Windows" else "安装.command"))
        self.assertEqual(self.runner.calls, [])

    def test_uac_cancellation_is_not_install_success(self):
        bridge = self.bridge("Windows", installed=False, runner=FakeRunner(stdout="", code=1223))
        self.assertEqual(bridge.run("install", confirmed=True)["state"], "cancelled")

    def test_process_and_reported_failures_empty_output_and_timeouts_never_succeed(self):
        for stdout, code in (("FAIL:copy failed", 0), ("STATUS=error\nMESSAGE=fixture", 0),
                             ("FIX:未恢复 ✗", 0), ("DNS=fail:fixture", 0), ("OK:fixture", 3), ("", 0)):
            bridge = self.bridge(runner=FakeRunner(stdout, code))
            self.assertEqual(bridge.run("fix", confirmed=True)["state"], "failed")
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output="secret-private")
        result = self.bridge(runner=timeout).run("fix", confirmed=True)
        self.assertEqual(result["state"], "unknown")
        self.assertNotIn("secret-private", json.dumps(result))

    def test_windows_does_not_reuse_stale_utf8_check_file(self):
        bridge = self.bridge("Windows", runner=FakeRunner(stdout="", code=0))
        output = self.home / ".claude-switcher/last-check.txt"
        output.write_text("出口IP=ok:stale", encoding="utf-8-sig")
        result = bridge.run("checkdetail", confirmed=True)
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("stale", result["stdout"])

    def test_windows_reads_only_fresh_utf8_check_result(self):
        bridge = self.bridge("Windows")
        output = self.home / ".claude-switcher/last-check.txt"
        def write_result(argv, **kwargs):
            output.write_text("出口IP=ok:8.8.8.8", encoding="utf-8-sig")
            return subprocess.CompletedProcess(argv, 0, "garbled stdout", "")
        bridge.runner = write_result
        result = bridge.run("checkdetail", confirmed=True)
        self.assertEqual(result["state"], "completed")
        self.assertIn("出口IP", result["stdout"])
        self.assertNotIn("garbled", result["stdout"])
        self.assertNotIn("8.8.8.8", result["stdout"])

    def test_reentrant_operation_is_blocked(self):
        bridge = self.bridge()
        bridge._lock.acquire()
        try:
            self.assertEqual(bridge.run("fix", confirmed=True)["reason"], "legacy_operation_running")
        finally:
            bridge._lock.release()
        self.assertEqual(self.runner.calls, [])

    def test_templates_are_references_not_auto_executed_services(self):
        catalog = self.bridge(installed=False).capabilities()
        self.assertEqual(len(catalog["templates"]), 5)
        self.assertTrue(all(not item["executable"] for item in catalog["templates"]))
        self.assertEqual(self.runner.calls, [])


if __name__ == "__main__":
    unittest.main()
