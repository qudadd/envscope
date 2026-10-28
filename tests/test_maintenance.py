"""No real scheduler, proxy, account, OS setting or remote endpoint is touched."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

from envscope.claude_checks import ITEMS
from envscope.maintenance import Maintenance
from envscope.model import Finding, Status, make_report
from envscope.operations import Operations
from envscope.policy import Policy
from envscope.remedies import ConfigRemedies, GUARDED_KEYS, SolutionPlans
from envscope.scheduler import UserScheduler, windows_xml, windows_identity, mac_plist, NS, MARKER, definition_text
from envscope.state import StateStore


def findings(ip="1.1.1.1"):
    result = [Finding("baseline." + key, title, Status.UNKNOWN, "fixture: not verified", "test-fixture")
              for key, title, *_ in ITEMS]
    if ip:
        result.append(Finding("http.egress", "egress", Status.PASS, "fixture HTTP sample", "test-fixture",
                              [{"ip": ip, "family": 4}]))
    result.append(Finding("dns.leak", "DNS", Status.UNKNOWN, "no authoritative observation", "test-fixture"))
    return result


class FakeScheduler:
    def __init__(self):
        self.definition = None
        self.calls = []
        self.fail = False

    def build(self, interval):
        return {"system": "fixture", "body": "fixture " + str(interval), "interval": interval}

    def inspect(self, spec=None):
        present = self.definition is not None
        owned = present and spec == self.definition
        return {"present": present, "owned": owned, "registered": owned, "state": "registered" if owned else "missing"}

    def install(self, spec, previous=None):
        self.calls.append(("install", spec))
        if self.fail:
            raise ValueError("fixture registration failure")
        self.definition = spec

    def remove(self, spec):
        self.calls.append(("remove", spec))
        if self.fail:
            raise ValueError("fixture removal failure")
        self.definition = None


class MaintenanceTests(unittest.TestCase):
    def test_region_change_blocks_background_restoration_before_any_write(self):
        self.enable(auto_restore=True)
        content=json.loads(self.path.read_text())
        content['env']['NODE_TLS_REJECT_UNAUTHORIZED']='0'
        self.path.write_text(json.dumps(content))
        before=self.path.read_bytes()
        def restricted(*args,**kwargs):
            values=findings()
            next(f for f in values if f.id=='baseline.country').evidence=[{'actual':'CN'}]
            return values
        self.auditor.side_effect=restricted
        result=self.manager.run_once()
        self.assertEqual(result['state'],'completed')
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(self.manager.status()['restore_state'],'paused')

    def test_region_failure_refuses_new_auto_restore_plan(self):
        from copy import deepcopy
        report=deepcopy(self.report)
        next(f for f in report['findings'] if f['id']=='target.region')['status']='fail'
        self.assertEqual(self.manager.prepare(report,5,True)['state'],'blocked')
        self.assertEqual(self.manager.prepare(report,5,False)['state'],'planned')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.store = StateStore(self.home / ".envscope")
        self.remedies = ConfigRemedies(self.home, self.home / "Claude", environ={})
        self.path = self.remedies.paths["cli"]
        self.path.parent.mkdir(parents=True)
        self.original = {"env": {"HTTPS_PROXY": "http://127.0.0.1:7897", "https_proxy": "http://127.0.0.1:7897",
                                 "NO_PROXY": "localhost", "no_proxy": "localhost", "NODE_TLS_REJECT_UNAUTHORIZED": "1",
                                 "PRIVATE_FIXTURE": "do-not-export"}, "permissions": {"allow": ["Read"]}}
        self.path.write_text(json.dumps(self.original), encoding="utf-8")
        self.scheduler = FakeScheduler()
        self.auditor = Mock(side_effect=lambda *a, **k: findings())
        self.proxy_tester = Mock(return_value=True)
        self.manager = Maintenance(self.store, self.remedies, self.scheduler, self.auditor, self.proxy_tester, self.home)
        self.report = make_report(findings(), Policy(), "one-click-desktop", self.store.settings())

    def enable(self, auto_restore=False):
        plan = self.manager.prepare(self.report, 5, auto_restore)
        self.assertEqual(plan["state"], "planned")
        result = self.manager.enable(plan["plan_id"], self.report, True)
        self.assertEqual(result["state"], "enabled")
        return plan

    def drift(self, **updates):
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data["env"].update(updates)
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def test_every_upstream_identity_has_observation_remedy_and_upkeep(self):
        items = self.report["claude_checks"]["items"]
        self.assertEqual(len(items), 14)
        self.assertEqual([x["number"] for x in items], list(range(1, 15)))
        self.assertEqual(len({x["id"] for x in items}), 14)
        for row in items:
            for field in ("measurement", "remedy", "upkeep", "source", "implementation"):
                self.assertTrue(row[field])
        dns = next(x for x in items if x["id"] == "dns")
        self.assertEqual(dns["status"], "unknown")
        self.assertIn("权威", dns["summary"] + dns["measurement"])

    def test_unset_locale_is_not_a_fault_and_asn_is_only_information(self):
        sample = findings()
        next(x for x in sample if x.id == "baseline.asn").status = Status.PASS
        rows = make_report(sample, Policy())["claude_checks"]["items"]
        self.assertEqual(next(x for x in rows if x["id"] == "locale")["status"], "not_configured")
        self.assertEqual(next(x for x in rows if x["id"] == "asn")["status"], "info")

    def test_prepare_is_read_only_and_explicit_confirmation_is_required(self):
        plan = self.manager.prepare(self.report, 15, True)
        self.assertEqual(plan["state"], "planned")
        self.assertFalse(self.manager.root.exists())
        self.assertFalse(self.scheduler.calls)
        for confirmed in (False, "true", 1):
            self.assertEqual(self.manager.enable(plan["plan_id"], self.report, confirmed)["state"], "confirmation_required")
        self.assertFalse(self.scheduler.calls)

    def test_only_fixed_intervals_and_booleans_are_accepted(self):
        for interval in (True, 1, 10, 999, "15"):
            with self.assertRaises(ValueError):
                self.manager.prepare(self.report, interval)
        with self.assertRaises(ValueError):
            self.manager.prepare(self.report, 15, "false")

    def test_disabled_worker_never_probes_or_writes_config(self):
        before = self.path.read_bytes()
        self.assertEqual(self.manager.run_once()["state"], "disabled")
        self.auditor.assert_not_called()
        self.proxy_tester.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    def test_stale_report_or_plan_cannot_install(self):
        old = deepcopy(self.report)
        old["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
        self.assertEqual(self.manager.prepare(old)["state"], "retest_required")
        plan = self.manager.prepare(self.report)
        self.manager.plans[plan["plan_id"]]["deadline"] = 0
        self.assertEqual(self.manager.enable(plan["plan_id"], self.report, True)["state"], "retest_required")
        self.assertFalse(self.scheduler.calls)

    def test_changed_config_or_preferences_invalidates_preview(self):
        plan = self.manager.prepare(self.report, 15, True)
        self.drift(OTHER="a new setting")
        self.assertEqual(self.manager.enable(plan["plan_id"], self.report, True)["state"], "retest_required")
        plan = self.manager.prepare(self.report)
        self.store.save_settings({"usage": "cli"})
        self.assertEqual(self.manager.enable(plan["plan_id"], self.report, True)["state"], "retest_required")

    def test_scheduler_failure_cannot_enable_recovery(self):
        self.scheduler.fail = True
        plan = self.manager.prepare(self.report, 5, True)
        self.assertEqual(self.manager.enable(plan["plan_id"], self.report, True)["state"], "failed")
        self.assertFalse(self.manager._config()["enabled"])
        self.assertEqual(self.manager.run_once()["state"], "disabled")

    def test_waiting_active_stale_and_failed_are_different_states(self):
        self.enable()
        self.assertEqual(self.manager.status()["state"], "waiting")
        self.assertEqual(self.manager.run_once()["state"], "completed")
        self.assertEqual(self.manager.status()["state"], "active")
        stats = self.manager._read("stats", {})
        stats["completed_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.manager._write("stats", stats)
        self.assertEqual(self.manager.status()["state"], "stale")
        self.auditor.side_effect = ValueError("fixture")
        self.assertEqual(self.manager.run_once()["state"], "failed")
        self.assertEqual(self.manager.status()["state"], "failed")

    def test_opt_in_recovery_preserves_unrelated_new_settings_and_secrets(self):
        self.enable(True)
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999", OTHER="new setting")
        result = self.manager.run_once()
        self.assertEqual(result["state"], "completed")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(data["env"]["HTTPS_PROXY"], self.original["env"]["HTTPS_PROXY"])
        self.assertEqual(data["env"]["OTHER"], "new setting")
        self.assertEqual(data["permissions"], self.original["permissions"])
        self.assertNotIn("do-not-export", json.dumps(result))
        self.assertNotIn("PRIVATE_FIXTURE", json.dumps(self.manager._config()))
        event = next(x for x in self.manager.status()["events"] if x["kind"] == "restored")
        self.assertEqual(event["keys"], ["HTTPS_PROXY"])
        self.assertTrue(event["backups"])

    def test_read_only_mode_reports_without_restoring_drift(self):
        self.enable(False)
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
        self.manager.run_once()
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))
        self.assertFalse(self.remedies.backups.exists())

    def test_deleted_or_malformed_config_is_never_overwritten(self):
        self.enable(True)
        for body in (b'{"env":', b'{"env":{},"env":{}}'):
            self.path.write_bytes(body)
            self.manager.run_once()
            self.assertEqual(self.path.read_bytes(), body)
        self.path.unlink()
        self.manager.run_once()
        self.assertFalse(self.path.exists())
        self.assertTrue(any(x["kind"] == "restore_blocked" for x in self.manager.status()["events"]))

    def test_unavailable_baseline_proxy_prevents_restore_without_direct_retry(self):
        self.enable(True)
        self.proxy_tester.return_value = False
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
        self.manager.run_once()
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))
        self.assertEqual(self.proxy_tester.call_args.args, ("http://127.0.0.1:7897",))
        self.assertEqual(self.manager.status()["state"], "attention")

    def test_repeated_rewrites_pause_restoration_at_three_per_day(self):
        self.enable(True)
        for _ in range(4):
            self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
            self.manager.run_once()
        status = self.manager.status()
        self.assertTrue(status["repair_paused"])
        self.assertEqual(len([x for x in status["events"] if x["kind"] == "restored"]), 3)
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))

    def test_setting_change_pauses_old_guard_but_checks_continue(self):
        self.enable(True)
        self.store.save_settings({"country": "JP"})
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
        self.assertEqual(self.manager.run_once()["state"], "completed")
        self.assertTrue(self.manager.status()["repair_paused"])
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))

    def test_48_hour_egress_tracking_uses_private_signatures_and_ignores_empty_samples(self):
        self.enable()
        for ip in ("1.1.1.1", "1.1.1.1", None, "8.8.8.8"):
            self.auditor.side_effect = lambda *a, ip=ip, **k: findings(ip)
            self.manager.run_once()
        self.assertEqual(self.manager.status()["egress_48h"], {"observations": 3, "changes": 1})
        self.assertNotIn("1.1.1.1", json.dumps(self.manager._read("egress", [])))
        report = self.manager.latest_report()["report"]
        self.assertEqual(report["mode"], "scheduled-native")
        self.assertEqual(next(x for x in report["findings"] if x["id"] == "maintenance.browser")["status"], "skipped")

    def test_undo_works_across_restart_and_refuses_later_edits(self):
        self.enable(True)
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
        self.manager.run_once()
        event = next(x for x in self.manager.status()["events"] if x["kind"] == "restored")
        token = event["backups"][0]["id"]
        repaired_bytes = self.path.read_bytes()
        fresh = ConfigRemedies(self.home, self.home / "Claude", environ={})
        records = fresh.list_backups()
        self.assertEqual(records[0]["id"], token)
        self.assertEqual(records[0]["availability"], "available")
        self.assertNotIn("do-not-export", json.dumps(records))
        self.drift(OTHER="later edit")
        with self.assertRaises(ValueError):
            fresh.undo(token, True)
        self.path.write_bytes(repaired_bytes)
        self.manager.disable(True)
        self.assertEqual(fresh.undo(token, True)["state"], "completed")
        self.assertEqual(fresh.list_backups()[0]["availability"], "undone")
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))
        with self.assertRaises(ValueError):
            ConfigRemedies(self.home, self.home / "Claude").undo(token, True)

    def test_disable_failure_still_blocks_all_future_repairs(self):
        self.enable(True)
        self.scheduler.fail = True
        self.assertEqual(self.manager.disable(True)["state"], "partial")
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
        self.assertEqual(self.manager.run_once()["state"], "disabled")
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))

    def test_never_started_job_becomes_stale_instead_of_waiting_forever(self):
        self.enable()
        config = self.manager._config()
        config["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.manager._write("config", config)
        self.assertEqual(self.manager.status()["state"], "stale")

    def test_new_comparison_key_does_not_create_a_false_egress_change(self):
        self.enable()
        self.manager.run_once()
        self.manager.data._write("history-key.private.json", "b" * 64)
        report = self.manager.run_once()["report"]
        self.assertEqual(self.manager.status()["egress_48h"], {"observations": 1, "changes": 0})
        self.assertEqual(next(f for f in report["findings"] if f["id"] == "baseline.ip_stability")["status"], "unknown")

    def test_unverifiable_repair_timestamps_pause_instead_of_resetting_budget(self):
        self.enable(True)
        stats = self.manager._read("stats", {})
        stats["repair_times"] = [(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()]
        self.manager._write("stats", stats)
        self.drift(HTTPS_PROXY="http://127.0.0.1:9999")
        self.manager.run_once()
        self.assertTrue(self.manager.status()["repair_paused"])
        self.assertIn("9999", self.path.read_text(encoding="utf-8"))

    def test_frozen_runtime_check_does_not_open_state_or_run_audits(self):
        from envscope.maintenance import main
        with patch("envscope.maintenance.Maintenance") as manager:
            self.assertEqual(main(["--check-runtime"]), 0)
            self.assertEqual(main(["--unknown"]), 3)
            manager.assert_not_called()

    def test_credentials_remote_proxies_bypass_and_disabled_tls_cannot_be_baselines(self):
        for update in ({"HTTPS_PROXY": "http://u:p@127.0.0.1:7897"}, {"HTTPS_PROXY": "http://example.com:7897"},
                       {"NO_PROXY": "api.anthropic.com"}, {"NODE_TLS_REJECT_UNAUTHORIZED": "0"}):
            self.path.write_text(json.dumps(self.original), encoding="utf-8")
            self.drift(**update)
            with self.assertRaises(ValueError):
                self.manager.prepare(self.report, 5, True)
        self.assertFalse(self.scheduler.calls)

    def test_operations_refuse_extra_parameters_and_unrelated_report(self):
        operations = Operations(self.store, home=self.home, maintenance=self.manager, discoverer=lambda: [])
        with self.assertRaises(ValueError):
            operations.run("maintenance-plan", {"report_id": self.report["report_id"], "command": "anything"}, report=self.report)
        self.assertEqual(operations.run("maintenance-plan", {"report_id": "old"}, report=self.report)["state"], "retest_required")
        for action in ("maintenance-enable", "maintenance-disable", "maintenance-undo"):
            self.assertEqual(operations.run(action, {}, confirmed="true", report=self.report)["state"], "confirmation_required")

    def test_cli_proxy_check_uses_native_config_fix_without_installing_system_helpers(self):
        self.drift(HTTPS_PROXY="socks5://127.0.0.1:7897")
        legacy = Mock()
        sample = findings() + [Finding("extra.cli_env", "Code", Status.WARN, "fixture SOCKS", "test-fixture",
                                       [{"installation_count":1,"config":{"exists":True,"valid":True},"proxy_scheme":"socks5"}])]
        report = make_report(sample, Policy(), "one-click-desktop", {"usage":"cli"})
        plans = SolutionPlans(self.remedies, legacy, lambda:[{"url":"http://127.0.0.1:7897"}],
                              lambda proxy:{"evidence":[{"endpoint":"https://api.anthropic.com/v1/models","http_status":401,"tls_verified":True}]})
        plan = plans.prepare(report, "proxy")
        self.assertEqual(plan["state"], "planned")
        self.assertEqual(plans.plans[plan["plan_id"]]["tasks"], ["config"])
        legacy.capabilities.assert_not_called()
        self.assertIn("socks5", self.path.read_text(encoding="utf-8"))


class ScheduleTests(unittest.TestCase):
    def test_user_jobs_register_verify_and_remove_using_only_fixed_actions(self):
        for system in ("Windows", "Darwin"):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
                state = {"loaded": False}
                calls = []
                def runner(args, **kwargs):
                    calls.append(args)
                    if args[0].endswith("powershell.exe"):
                        value = {"present": state["loaded"]}
                        if state["loaded"]:
                            value["xml"] = definition_text(scheduler.path.read_bytes())
                        return subprocess.CompletedProcess(args, 0, json.dumps(value), "")
                    if "/Create" in args or "bootstrap" in args:
                        state["loaded"] = True
                    elif "/Delete" in args or "bootout" in args:
                        state["loaded"] = False
                    return subprocess.CompletedProcess(args, 0 if state["loaded"] or "print" not in args else 1, "", "")
                scheduler = UserScheduler(directory, Path(directory) / "maintenance", system=system,
                                          runner=runner, sid="S-1-5-21-123", uid=501,
                                          command=[str(Path(directory)/'EnvScope'), '--maintenance-worker'],cwd=directory)
                spec = scheduler.build(5)
                self.assertEqual(scheduler.install(spec)["state"], "registered")
                self.assertTrue(scheduler.inspect(spec)["registered"])
                self.assertEqual(scheduler.remove(spec)["state"], "removed")
                self.assertFalse(scheduler.path.exists())
                self.assertTrue(all("shell" not in c for c in calls))

    def test_windows_task_is_user_scoped_fixed_command_and_escaped(self):
        command = [r"C:\A & B\EnvScope.exe", "--maintenance-worker"]
        body = windows_xml(command, r"C:\A & B", 5, "S-1-5-21-123")
        self.assertTrue(body.startswith((b"\xff\xfe", b"\xfe\xff")))
        self.assertIn("encoding='utf-16'", definition_text(body))
        self.assertEqual(definition_text(b"<legacy-utf8/>"), "<legacy-utf8/>")
        value = windows_identity(body)
        self.assertEqual(value["program"], command[0])
        self.assertEqual(value["arguments"], "--maintenance-worker")
        self.assertEqual(value["interval"], "PT5M")
        self.assertEqual(value["level"], "LeastPrivilege")
        self.assertEqual(value["logon"], "InteractiveToken")
        self.assertEqual(value["marker"], MARKER)
        # Microsoft triggerBaseType is a sequence: Enabled, StartBoundary,
        # EndBoundary, Repetition, ExecutionTimeLimit. Test the actual ordering.
        tree = ET.fromstring(body)
        trigger = tree.find("{" + NS + "}Triggers/{" + NS + "}TimeTrigger")
        self.assertEqual([n.tag.rsplit("}", 1)[-1] for n in trigger], ["Enabled", "StartBoundary", "Repetition"])
        self.assertEqual(tree.attrib["version"], "1.3")

    def test_mac_job_uses_argument_array_and_has_no_root_or_shell(self):
        command = ["/Users/test/A & B/EnvScope", "--maintenance-worker"]
        value = plistlib.loads(mac_plist(command, "/Users/test/A & B", 15))
        self.assertEqual(value["ProgramArguments"], command)
        self.assertEqual(value["StartInterval"], 900)
        self.assertNotIn("UserName", value)
        self.assertNotIn("KeepAlive", value)

    def test_windows_export_elided_defaults_still_requires_matching_identity_and_enabled_triggers(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = UserScheduler(directory, Path(directory)/"maintenance", system="Windows", sid="S-1-5-21-123")
            spec = scheduler.build(5)
            tree = ET.fromstring(spec["body"])
            paths = ("Settings/Enabled", "Principals/Principal/RunLevel", "Triggers/LogonTrigger/Enabled", "Triggers/TimeTrigger/Enabled")
            for path in paths:
                parts = ["{"+NS+"}"+v for v in path.split("/")]
                parent = tree.find('/'.join(parts[:-1]))
                parent.remove(parent.find(parts[-1]))
            def runner(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, json.dumps({"present":True,"xml":ET.tostring(tree,encoding='unicode')}), "")
            scheduler.runner = runner
            self.assertTrue(scheduler.inspect(spec)["registered"])
            trigger = tree.find("{"+NS+"}Triggers/{"+NS+"}TimeTrigger")
            ET.SubElement(trigger, "{"+NS+"}Enabled").text = "false"
            self.assertTrue(scheduler.inspect(spec)["owned"])
            self.assertFalse(scheduler.inspect(spec)["registered"])
            trigger.find("{"+NS+"}Enabled").text = None
            self.assertFalse(scheduler.inspect(spec)["registered"], "an empty element is not absence")
            principal = tree.find("{"+NS+"}Principals/{"+NS+"}Principal/{"+NS+"}UserId")
            principal.text = "S-1-5-21-999"
            self.assertFalse(scheduler.inspect(spec)["owned"])

    def test_foreign_or_unreadable_windows_task_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({"present": True, "xml": "<invalid/>"}), ""))
            scheduler = UserScheduler(directory, Path(directory) / "maintenance", system="Windows", runner=runner, sid="S-1-5-21-123")
            spec = scheduler.build(5)
            with self.assertRaises(ValueError):
                scheduler.install(spec)
            self.assertFalse(scheduler.path.exists())
            self.assertTrue(all("/Create" not in call.args[0] for call in runner.call_args_list))

    def test_changed_mac_definition_is_preserved_on_remove(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = UserScheduler(directory, Path(directory) / "maintenance", system="Darwin", uid=501,
                                      runner=Mock(return_value=subprocess.CompletedProcess([], 1, "", "")))
            spec = scheduler.build(5)
            scheduler.path.parent.mkdir(parents=True)
            body = plistlib.loads(spec["body"].encode())
            body["ProgramArguments"] = ["/different/tool"]
            scheduler.path.write_bytes(plistlib.dumps(body))
            with self.assertRaises(ValueError):
                scheduler.remove(spec)
            self.assertTrue(scheduler.path.exists())


if __name__ == "__main__":
    unittest.main()
