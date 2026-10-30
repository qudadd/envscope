import subprocess
import unittest

from envscope.consent import ConsentError, raise_for_consent, operation_outcome


class ConsentTests(unittest.TestCase):
    def test_only_native_cancel_codes_mean_cancelled(self):
        for system, code, stderr, expected in (
            ('Windows', 1223, '', 'consent_cancelled'), ('Windows', 1260, '', 'policy_denied'),
            ('Darwin', 1, 'execution error: User canceled. (-128)', 'consent_cancelled'),
            ('Darwin', 1, 'operation failed; cancelled string PRIVATE_CREDENTIAL', 'operation_failed'),
            ('Windows', 1, 'cancelled string', 'operation_failed')):
            with self.subTest(system=system, expected=expected):
                with self.assertRaises(ConsentError) as error:
                    raise_for_consent(subprocess.CompletedProcess([], code, '', stderr), system)
                self.assertEqual(operation_outcome(error.exception)['error'], expected)
                self.assertNotIn('PRIVATE_CREDENTIAL', str(error.exception))

    def test_timeout_is_unknown_execution_not_cancelled(self):
        value = operation_outcome(subprocess.TimeoutExpired('fixture', 1))
        self.assertEqual(value['error'], 'execution_unknown')
        self.assertTrue(value['needs_retest'])

    def test_successful_command_still_requires_callers_independent_readback(self):
        self.assertIsNone(raise_for_consent(subprocess.CompletedProcess([], 0, '', ''), 'Darwin'))
