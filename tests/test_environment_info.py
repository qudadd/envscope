import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from envscope.check_catalog import check_catalog
from envscope.environment_info import cli_information, device_information
from envscope.extended import CHECKS
from envscope.operations import Operations
from envscope.state import StateStore


class EnvironmentInformationTests(unittest.TestCase):
    def test_missing_cli_is_explained_without_execution_or_file_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            value = cli_information(directory, which=lambda name: None)
            self.assertFalse(value['config_exists'])
            self.assertIn('未找到', value['rows'][0]['value'])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_windows_unicode_json_uses_explicit_encoding_and_no_secrets(self):
        reader = Mock(return_value={'machine': {'Manufacturer': '测试厂商', 'Model': '测试型号', 'SerialNumber': 'PRIVATE'},
                                    'gpu': [{'Name': '显卡', 'DriverVersion': '1.2'}], 'font_count': 8})
        value = device_information('Windows', reader)
        self.assertEqual(value['state'], 'completed')
        self.assertIn('测试型号', str(value))
        self.assertNotIn('PRIVATE', str(value))
        self.assertIn('OutputEncoding', reader.call_args.args[0][-1])

    def test_failures_preserve_basic_information_and_do_not_become_success(self):
        for failure in (OSError(), ValueError(), subprocess.TimeoutExpired('fixture', 12)):
            value = device_information('Windows', Mock(side_effect=failure))
            self.assertEqual(value['state'], 'partial')
            self.assertGreaterEqual(len(value['rows']), 2)
            self.assertIn('未能', value['note'])

    def test_mac_device_read_is_native_and_drops_unneeded_identifiers(self):
        reader = Mock(return_value={'SPDisplaysDataType': [{'sppci_model': 'Apple fixture', 'serial_number': 'PRIVATE'}]})
        value = device_information('Darwin', reader)
        self.assertEqual(value['state'], 'completed')
        self.assertIn('Apple fixture', str(value))
        self.assertNotIn('PRIVATE', str(value))
        self.assertNotIn('SPHardwareDataType', reader.call_args.args[0])

    def test_catalog_covers_actual_checks_without_synthetic_results(self):
        rows = check_catalog()
        self.assertEqual(len(rows), 57)
        self.assertEqual(len({r['id'] for r in rows}), 57)
        self.assertTrue(any(r['id']=='target.region' for r in rows))
        self.assertEqual({r['id'] for r in rows if r['group'] == 'extra'}, {'extra.' + k for k, _ in CHECKS})
        self.assertTrue(all(r['why'] and r['next_step'] and r['upkeep'] for r in rows))
        self.assertFalse(any('status' in r for r in rows))

    def test_information_actions_do_not_require_legacy_on_either_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Mock()
            legacy.run.side_effect = AssertionError('Legacy must not run')
            operations = Operations(StateStore(memory=True), directory, legacy=legacy, discoverer=lambda: [])
            for system in ('Windows', 'Darwin'):
                with self.subTest(system=system), patch('envscope.operations.platform.system', return_value=system), patch('envscope.operations.cli_information', return_value={'rows': []}) as cli, patch('envscope.operations.device_information', return_value={'rows': []}) as device:
                    operations.run('cli-info', {})
                    operations.run('fingerprint', {})
                    cli.assert_called_once();device.assert_called_once()
                    legacy.run.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_information_actions_reject_supplied_commands_before_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            operations = Operations(StateStore(memory=True), directory, discoverer=lambda: [])
            with patch('envscope.operations.device_information') as device, patch('envscope.operations.cli_information') as cli:
                for action in ('cli-info', 'fingerprint'):
                    with self.assertRaises(ValueError):
                        operations.run(action, {'command': 'unexpected'})
                device.assert_not_called();cli.assert_not_called()

    def test_legacy_detailed_reader_is_preserved_as_an_explicit_fixed_action(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Mock()
            legacy.run.return_value = {'state': 'unavailable'}
            operations = Operations(StateStore(memory=True), directory, legacy=legacy, discoverer=lambda: [])
            value = operations.run('legacy-cli-info', {})
            self.assertEqual(value['state'], 'unavailable')
            self.assertEqual(legacy.run.call_args.args, ('cli-info', {}))
