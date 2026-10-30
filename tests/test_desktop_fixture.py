"""Fixture setup failures return evidence instead of launching the real app."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from envscope import desktop


class DesktopFixtureTests(unittest.TestCase):
    def test_setup_exception_returns_failure_metadata_without_normal_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'evidence.json'
            with patch('sys.argv',['envscope','--desktop-smoke',str(output)]),patch('envscope._desktop_test.main',side_effect=ValueError('owned fixture failure')),patch('envscope.desktop.make_server') as normal:
                self.assertEqual(desktop.main(),1)
                normal.assert_not_called()
            value=json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(value['errors'],['ValueError: owned fixture failure'])
            self.assertNotIn('native_window',value)

    def test_invalid_fixture_arguments_never_fall_through_to_real_application(self):
        for args in (['envscope','--desktop-smoke'],['envscope','--desktop-smoke','one','extra']):
            with patch('sys.argv',args),patch('envscope.desktop.make_server') as normal:
                with self.assertRaises(SystemExit) as error:desktop.main()
                self.assertEqual(error.exception.code,2)
                normal.assert_not_called()
