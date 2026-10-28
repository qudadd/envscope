"""The real-OS acceptance harness must never run against a developer host."""
from unittest import TestCase
from unittest.mock import patch

from scripts.scheduler_acceptance import main


class AcceptanceBoundaryTests(TestCase):
    def test_explicit_disposable_ci_opt_in_is_required_before_any_scheduler_use(self):
        for values in ({}, {"GITHUB_ACTIONS": "true"}, {"ENVSCOPE_SCHEDULER_ACCEPTANCE": "1"},
                       {"GITHUB_ACTIONS": "false", "ENVSCOPE_SCHEDULER_ACCEPTANCE": "1"}):
            with self.subTest(values=values), patch.dict('os.environ', values, clear=True), patch('builtins.print'), patch('scripts.scheduler_acceptance.UserScheduler') as scheduler:
                self.assertEqual(main([]), 2)
                scheduler.assert_not_called()
