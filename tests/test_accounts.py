"""Account operations use temporary profiles and injected callbacks only."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from envscope.accounts import (AccountError, AccountManager, PreflightError,
                               RecoveryRequired, _copy_verified, validate_slot)
import envscope.accounts as accounts


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.data = self.root / "Claude"
        self.events = []
        self.manager = AccountManager(self.state, self.data, "current.txt",
                                      lambda: self.events.append("stop") or True,
                                      lambda: self.events.append("launch") or True)

    def tearDown(self):
        self.temporary.cleanup()

    def profile(self, directory, text):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "session.txt").write_text(text, encoding="utf-8")
        (directory / "empty").mkdir(exist_ok=True)

    def seed(self):
        self.profile(self.data, "A live newest")
        self.profile(self.state / "accounts" / "A", "A older archive")
        self.profile(self.state / "accounts" / "B", "B archive")
        (self.state / "current.txt").write_text("A", encoding="utf-8")

    def text(self, directory):
        return (directory / "session.txt").read_text(encoding="utf-8")

    def preflight(self):
        self.events.append("preflight")
        return True

    def assert_seed_preserved(self):
        self.assertEqual(self.text(self.data), "A live newest")
        self.assertEqual(self.text(self.state / "accounts" / "A"), "A older archive")
        self.assertEqual(self.text(self.state / "accounts" / "B"), "B archive")
        self.assertEqual((self.state / "current.txt").read_text(), "A")
        self.assertEqual(self.manager.list_accounts()["pending"], [])

    def test_construction_and_list_are_read_only(self):
        result = self.manager.list_accounts()
        self.assertEqual(result["current"], None)
        self.assertEqual([a["slot"] for a in result["accounts"]], list("ABCD"))
        self.assertFalse(self.state.exists())
        self.assertFalse(self.data.exists())
        self.assertEqual(self.events, [])

    def test_switch_archives_newest_and_keeps_target_snapshot(self):
        self.seed()
        result = self.manager.switch("B", self.preflight)
        self.assertEqual(result, {"slot": "B", "previous": "A", "changed": True,
                                  "launched": True, "warnings": []})
        self.assertEqual(self.events, ["preflight", "stop", "launch"])
        self.assertEqual(self.text(self.data), "B archive")
        self.assertEqual(self.text(self.state / "accounts" / "A"), "A live newest")
        self.assertEqual(self.text(self.state / "accounts" / "B"), "B archive")
        self.assertTrue((self.data / "empty").is_dir())
        self.assertEqual(self.manager.list_accounts()["pending"], [])
        self.assertEqual(self.manager.list_accounts()["current"], "B")

    def test_round_trip_retains_per_account_changes(self):
        self.seed()
        self.manager.switch("B", self.preflight)
        (self.data / "session.txt").write_text("B newest")
        self.manager.switch("A", self.preflight)
        self.assertEqual(self.text(self.data), "A live newest")
        self.assertEqual(self.text(self.state / "accounts" / "B"), "B newest")

    def test_long_copy_requires_renewed_preflight_before_launch(self):
        self.seed()
        answers = iter([True, False])
        with patch("envscope.accounts.time.monotonic", side_effect=[0, 46]):
            result = self.manager.switch("B", lambda: next(answers))
        self.assertFalse(result["launched"])
        self.assertIn("renewed preflight", result["warnings"][0])
        self.assertEqual(self.text(self.data), "B archive")
        self.assertEqual(self.manager.list_accounts()["current"], "B")
        self.assertEqual(self.manager.list_accounts()["pending"], [])
        self.assertNotIn("launch", self.events)

    def test_long_copy_can_launch_after_renewed_preflight(self):
        self.seed()
        with patch("envscope.accounts.time.monotonic", side_effect=[0, 46]):
            result = self.manager.switch("B", self.preflight)
        self.assertTrue(result["launched"])
        self.assertEqual(self.events, ["preflight", "stop", "preflight", "launch"])

    def test_first_run_adopts_current_data_as_a(self):
        self.profile(self.data, "untracked original")
        self.manager.switch("B", self.preflight)
        self.assertEqual(self.text(self.state / "accounts" / "A"), "untracked original")
        self.assertEqual(list(self.data.iterdir()), [])
        self.assertEqual(self.manager.list_accounts()["current"], "B")

    def test_first_run_a_restores_adopted_identity(self):
        self.profile(self.data, "untracked original")
        self.manager.switch("A", self.preflight)
        self.assertEqual(self.text(self.data), "untracked original")
        self.assertEqual(self.text(self.state / "accounts" / "A"), "untracked original")

    def test_same_current_only_launches_after_preflight(self):
        self.seed()
        result = self.manager.switch("A", self.preflight)
        self.assertFalse(result["changed"])
        self.assertEqual(self.events, ["preflight", "launch"])
        self.assert_seed_preserved()

    def test_desktop_launch_and_restart_keep_all_profiles_and_markers(self):
        self.seed()
        for restart in (False, True):
            self.events.clear()
            result = self.manager.launch_checked(self.preflight, self.manager.launch_app, restart, self.manager.stop_app)
            self.assertTrue(result["launched"])
            self.assertFalse(result["profiles_changed"])
            self.assertEqual(self.events, ["preflight", "stop", "preflight", "launch"] if restart else ["preflight", "launch"])
            self.assert_seed_preserved()

    def test_restart_requires_confirmed_exit_and_a_second_fresh_measurement(self):
        self.seed()
        result = self.manager.launch_checked(self.preflight, self.manager.launch_app, True, lambda: False)
        self.assertFalse(result["launched"])
        self.assertFalse(result["stop_confirmed"])
        self.assertNotIn("launch", self.events)
        answers = iter([True, False])
        with self.assertRaises(PreflightError):
            self.manager.launch_checked(lambda: next(answers), self.manager.launch_app, True, self.manager.stop_app)
        self.assertNotIn("launch", self.events)
        self.assert_seed_preserved()

    def test_launch_refuses_pending_missing_live_and_concurrent_account_state(self):
        self.seed()
        self.profile(self.data.with_name("Claude.previous"), "unique recovery")
        with self.assertRaises(RecoveryRequired):
            self.manager.launch_checked(self.preflight, self.manager.launch_app)
        self.assertEqual(self.text(self.data.with_name("Claude.previous")), "unique recovery")
        self.assertNotIn("launch", self.events)
        # A separate fresh profile fixture covers a missing tracked live tree.
        other = AccountManager(self.root / "other-state", self.root / "missing")
        other.state_dir.mkdir()
        (other.state_dir / "current.txt").write_text("A")
        self.assertFalse(other.inspect_integrity()["valid"])
        with self.assertRaises(RecoveryRequired):
            other.launch_checked(self.preflight, self.manager.launch_app)
        with self.manager._lock(), self.assertRaises(AccountError):
            AccountManager(self.state, self.data).launch_checked(self.preflight, self.manager.launch_app)
        self.assertNotIn("launch", self.events)

    def test_false_unknown_and_exception_preflight_do_not_write_or_stop(self):
        for value in (False, None, {}, 1):
            with self.assertRaises(PreflightError):
                self.manager.switch("B", lambda: value)
        with self.assertRaises(PreflightError):
            self.manager.switch("B", lambda: (_ for _ in ()).throw(RuntimeError("fixture")))
        self.assertEqual(self.events, [])
        self.assertFalse(self.state.exists())

    def test_missing_preflight_and_stop_callback_refuse(self):
        with self.assertRaises(PreflightError):
            self.manager.switch("B", None)
        unsafe = AccountManager(self.state, self.data, stop_app=None)
        with self.assertRaises(AccountError):
            unsafe.switch("B", lambda: True)
        self.assertFalse(self.data.exists())

    def test_failed_stop_preserves_all_profiles(self):
        self.seed()
        self.manager.stop_app = lambda: False
        with self.assertRaises(AccountError):
            self.manager.switch("B", self.preflight)
        self.assert_seed_preserved()
        self.assertNotIn("launch", self.events)

    def test_invalid_slots_rejected_before_preflight(self):
        for value in ("../B", "/B", "B.new", "A/B", "B\\C", "", "x" * 33,
                      "$(whoami)", "CON", "com1", "LPT9", "中文", None):
            with self.subTest(value=value), self.assertRaises(AccountError):
                self.manager.switch(value, self.preflight)
        self.assertEqual(self.events, [])
        self.assertEqual(validate_slot("a"), "A")
        self.assertEqual(validate_slot("project_1-new"), "project_1-new")

    def test_dynamic_label_does_not_move_snapshot_or_identity(self):
        self.manager.rename_label("project_1-new", "工作账号")
        result = self.manager.list_accounts()
        dynamic = next(a for a in result["accounts"] if a["slot"] == "project_1-new")
        self.assertEqual(dynamic["label"], "工作账号")
        self.assertFalse(dynamic["has_snapshot"])
        self.assertEqual(self.events, [])
        self.manager.switch("project_1-new", self.preflight)
        self.assertEqual(self.manager.list_accounts()["current"], "project_1-new")
        self.manager.rename_label("project_1-new", "新标签")
        self.assertEqual(self.manager.list_accounts()["current"], "project_1-new")
        self.manager.rename_label("project_1-new", "")
        self.assertNotIn("project_1-new", json.loads(self.manager.labels_file.read_text())["labels"])

    def test_case_collisions_and_label_controls_refused(self):
        self.manager.rename_label("Project", "one")
        with self.assertRaises(AccountError):
            self.manager.rename_label("project", "two")
        with self.assertRaises(AccountError):
            self.manager.rename_label("B", "bad\nlabel")
        with self.assertRaises(AccountError):
            self.manager.rename_label("B", "x" * 81)

    def test_legacy_marker_fallback_and_dual_marker_updates(self):
        self.seed()
        (self.state / "current.txt").rename(self.state / "current")
        self.assertEqual(self.manager.list_accounts()["current"], "A")
        self.manager.switch("B", self.preflight)
        self.assertEqual((self.state / "current").read_text().strip(), "B")
        self.assertEqual((self.state / "current.txt").read_text().strip(), "B")

    def test_disagreeing_current_markers_refused(self):
        self.seed()
        (self.state / "current").write_text("B")
        with self.assertRaises(RecoveryRequired):
            self.manager.switch("B", self.preflight)
        self.assertEqual(self.events, ["preflight"])
        self.assertEqual(self.text(self.data), "A live newest")

    def test_pending_stages_are_preserved_and_block_process_actions(self):
        self.seed()
        for path in (self.state / "accounts" / "A.new", self.state / "accounts" / "B.previous",
                     self.data.with_name("Claude.new"), self.data.with_name("Claude.previous")):
            with self.subTest(path=path):
                self.profile(path, "unique recovery copy")
                with self.assertRaises(RecoveryRequired):
                    self.manager.switch("B", self.preflight)
                self.assertEqual(self.text(path), "unique recovery copy")
                self.assertNotIn("stop", self.events)
                import shutil
                shutil.rmtree(path)

    def test_partial_copy_failure_rolls_back_without_touching_live(self):
        self.seed()
        count = 0
        def failing_copy(source, destination):
            nonlocal count
            count += 1
            if count == 2:
                self.profile(destination, "partial copy")
                raise OSError("fixture disk full")
            return _copy_verified(source, destination)
        with patch.object(accounts, "_copy_verified", side_effect=failing_copy):
            with self.assertRaises(AccountError):
                self.manager.switch("B", self.preflight)
        self.assert_seed_preserved()
        self.assertNotIn("launch", self.events)

    def test_live_commit_failure_restores_live_and_old_archive(self):
        self.seed()
        real_replace = os.replace
        def failing_replace(source, destination):
            if Path(source) == self.data.with_name("Claude.new") and Path(destination) == self.data:
                raise OSError("fixture rename failed")
            return real_replace(source, destination)
        with patch.object(accounts.os, "replace", side_effect=failing_replace):
            with self.assertRaises(AccountError):
                self.manager.switch("B", self.preflight)
        self.assert_seed_preserved()
        self.assertNotIn("launch", self.events)

    def test_marker_write_failure_rolls_back_full_exchange(self):
        self.seed()
        with patch.object(self.manager, "_write_current", side_effect=OSError("fixture marker failure")):
            with self.assertRaises(AccountError):
                self.manager.switch("B", self.preflight)
        self.assert_seed_preserved()

    def test_cleanup_failure_keeps_committed_state_and_refuses_launch(self):
        self.seed()
        with patch.object(accounts, "_remove_staging", side_effect=OSError("fixture cleanup failure")):
            with self.assertRaises(RecoveryRequired):
                self.manager.switch("B", self.preflight)
        self.assertEqual(self.text(self.data), "B archive")
        self.assertEqual(self.text(self.data.with_name("Claude.previous")), "A live newest")
        self.assertEqual(self.manager.list_accounts()["current"], "B")
        self.assertTrue(self.manager.list_accounts()["pending"])
        self.assertNotIn("launch", self.events)

    def test_original_old_and_new_upstream_staging_are_retained_and_block_native_switch(self):
        self.seed()
        legacy=self.data.with_name('Claude.old');self.profile(legacy,'LEGACY_NEWEST_FIXTURE')
        staged=self.state/'staging/Claude.new';self.profile(staged,'UPSTREAM_STAGE_FIXTURE')
        previous=self.state/'staging/Claude.old';self.profile(previous,'UPSTREAM_PREVIOUS_FIXTURE')
        marker=self.state/'staging/cleanup.json';marker.write_text('{"version":1,"target":"A"}',encoding='utf-8')
        before={path:accounts._manifest(path) for path in (legacy,staged,previous,self.data)}
        self.assertEqual(self.manager._pending(),['legacy-profile/Claude.old','legacy-staging/Claude.new','legacy-staging/Claude.old','legacy-staging/cleanup.json'])
        with self.assertRaises(RecoveryRequired):self.manager.switch('B',lambda:True)
        with self.assertRaises(RecoveryRequired):
            self.manager.launch_checked(lambda:True,lambda:self.events.append('launch'))
        self.assertEqual(self.events,[])
        self.assertEqual(self.manager.list_accounts()['current'],'A')
        for path,manifest in before.items():self.assertEqual(accounts._manifest(path),manifest)
        self.assertTrue(marker.exists())
        self.assertFalse(self.manager.recovery.status().get('available',False))
        self.assertIn('Claude.old',self.manager.recovery.plan()['manual'])

    def test_launch_failure_does_not_undo_safe_committed_profile(self):
        self.seed()
        self.manager.launch_app = lambda: False
        result = self.manager.switch("B", self.preflight)
        self.assertFalse(result["launched"])
        self.assertTrue(result["warnings"])
        self.assertEqual(self.text(self.data), "B archive")
        self.assertEqual(self.manager.list_accounts()["current"], "B")

    def test_missing_current_live_can_restore_its_snapshot(self):
        self.profile(self.state / "accounts" / "A", "A recovery")
        (self.state / "current.txt").write_text("A")
        with self.assertRaises(RecoveryRequired):
            self.manager.switch("B", self.preflight)
        self.manager.switch("A", self.preflight)
        self.assertEqual(self.text(self.data), "A recovery")

    def test_untracked_profile_cannot_overwrite_existing_a(self):
        self.profile(self.data, "untracked")
        self.profile(self.state / "accounts" / "A", "archived A")
        with self.assertRaises(RecoveryRequired):
            self.manager.switch("B", self.preflight)
        self.assertEqual(self.text(self.data), "untracked")
        self.assertEqual(self.text(self.state / "accounts" / "A"), "archived A")
        self.assertNotIn("stop", self.events)

    def test_nested_symlink_refused_without_following_it(self):
        self.seed()
        outside = self.root / "outside.txt"
        outside.write_text("private fixture")
        try:
            (self.data / "link.txt").symlink_to(outside)
        except OSError:
            self.skipTest("Symlink permission is unavailable")
        with self.assertRaises(AccountError):
            self.manager.switch("B", self.preflight)
        self.assertEqual(outside.read_text(), "private fixture")
        self.assertNotIn("stop", self.events)

    def test_simulated_reparse_point_refused(self):
        self.seed()
        real_redirect = accounts._redirect
        with patch.object(accounts, "_redirect", side_effect=lambda p: p == self.data or real_redirect(p)):
            with self.assertRaises(AccountError):
                self.manager.switch("B", self.preflight)
        self.assertEqual(self.text(self.data), "A live newest")
        self.assertNotIn("stop", self.events)

    def test_raw_export_import_hooks_verify_without_process_actions(self):
        self.seed()
        destination = self.root / "raw-export"
        result = self.manager.copy_snapshot_to("B", destination)
        self.assertFalse(result["encrypted"])
        self.assertEqual(self.text(destination), "B archive")
        self.manager.import_snapshot_from(destination, "project")
        self.assertEqual(self.text(self.state / "accounts" / "project"), "B archive")
        self.assertEqual(self.events, [])
        with self.assertRaises(AccountError):
            self.manager.copy_snapshot_to("A", self.root / "active-export")
        with self.assertRaises(AccountError):
            self.manager.import_snapshot_from(destination, "B")
        with self.assertRaises(AccountError):
            self.manager.copy_snapshot_to("B", self.state / "accounts" / "B" / "nested")

    def test_opt_in_retention_merges_into_stage_without_changing_target_archive(self):
        self.seed()
        (self.data / "settings.json").write_text("shared settings")
        (self.data / "skills").mkdir()
        (self.data / "skills" / "shared.txt").write_text("shared skill")
        target = self.state / "accounts" / "B"
        (target / "settings.json").write_text("B old settings")
        (target / "skills").mkdir()
        (target / "skills" / "own.txt").write_text("B skill")
        self.manager.keep_file.write_text("# optional\nskills/\nskills/missing.json\n")
        self.manager.switch("B", self.preflight)
        self.assertEqual((self.data / "settings.json").read_text(), "B old settings")
        self.assertEqual((self.data / "skills" / "shared.txt").read_text(), "shared skill")
        self.assertEqual((self.data / "skills" / "own.txt").read_text(), "B skill")
        self.assertEqual((target / "settings.json").read_text(), "B old settings")
        self.assertFalse((target / "skills" / "shared.txt").exists())
        self.assertEqual(self.text(self.data), "B archive")

    def test_retention_defaults_off_and_traversal_is_refused(self):
        self.seed()
        (self.data / "settings.json").write_text("A settings")
        self.manager.switch("B", self.preflight)
        self.assertFalse((self.data / "settings.json").exists())
        self.manager.keep_file.write_text("../outside.txt")
        before_events = list(self.events)
        with self.assertRaises(AccountError):
            self.manager.switch("C", self.preflight)
        self.assertEqual(self.events, before_events + ["preflight"])
        self.assertEqual(self.text(self.data), "B archive")
        self.assertEqual(self.manager.list_accounts()["current"], "B")

    def test_retention_failure_keeps_live_data_and_prevents_launch(self):
        self.seed()
        self.manager.keep_file.write_text("skills/")
        with patch.object(self.manager, "_merge_retained", side_effect=OSError("fixture merge failure")):
            with self.assertRaises(AccountError):
                self.manager.switch("B", self.preflight)
        self.assert_seed_preserved()
        self.assertNotIn("launch", self.events)

    def test_legacy_retention_stage_is_preserved_for_manual_recovery(self):
        self.seed()
        stage = self.state / "keep-stage"
        self.profile(stage, "sole legacy retention copy")
        with self.assertRaises(RecoveryRequired):
            self.manager.switch("B", self.preflight)
        self.assertEqual(self.text(stage), "sole legacy retention copy")
        self.assertNotIn("stop", self.events)

    def test_verifier_rejects_corrupted_copy(self):
        self.profile(self.root / "source", "original")
        real_copy = accounts.shutil.copy2
        def corrupt(source, destination, **kwargs):
            result = real_copy(source, destination, **kwargs)
            if Path(destination).name == "session.txt":
                Path(destination).write_text("corrupt")
            return result
        with patch.object(accounts, "copy_profile_file", side_effect=corrupt):
            with self.assertRaises(AccountError):
                _copy_verified(self.root / "source", self.root / "copy")
        self.assertEqual(self.text(self.root / "source"), "original")

    def test_concurrent_mutation_refused_without_waiting_or_overwriting(self):
        other = AccountManager(self.state, self.data, "current.txt")
        with self.manager._lock():
            with self.assertRaises(AccountError):
                other.rename_label("B", "competing writer")
        self.assertFalse(self.manager.labels_file.exists())

    def test_journal_survives_failed_rollback_and_blocks_later_actions(self):
        self.seed()
        real_replace = os.replace
        def failing_replace(source, destination):
            if Path(destination) == self.data and Path(source).name in {"Claude.new", "Claude.previous"}:
                raise OSError("fixture commit and rollback failure")
            return real_replace(source, destination)
        with patch.object(accounts.os, "replace", side_effect=failing_replace):
            with self.assertRaises(RecoveryRequired):
                self.manager.switch("B", self.preflight)
        self.assertTrue(self.manager.journal_file.exists())
        self.assertEqual(self.text(self.data.with_name("Claude.previous")), "A live newest")
        self.assertEqual(self.text(self.data.with_name("Claude.new")), "B archive")
        self.assertNotIn("launch", self.events)
        with self.assertRaises(RecoveryRequired):
            self.manager.switch("A", self.preflight)

    def test_overlapping_storage_paths_refused(self):
        with self.assertRaises(AccountError):
            AccountManager(self.root, self.root / "Claude")
        with self.assertRaises(AccountError):
            AccountManager(self.root / "state", self.root)


if __name__ == "__main__":
    unittest.main()
