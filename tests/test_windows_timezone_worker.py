"""Compiled fixture has no OS clock-writing branch; only disposable files change."""
import configparser
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == 'Windows', 'Windows native compiler required')
class WindowsTimezoneWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from scripts.build_windows_timezone import build
        cls.build_dir = tempfile.TemporaryDirectory()
        try:
            cls.folder = build(cls.build_dir.name, fixture=True)
        except RuntimeError as error:
            cls.build_dir.cleanup()
            raise RuntimeError('Native worker fixture build failed: ' + str(error)) from None
        cls.exe = cls.folder / 'timezone-helper.exe'

    @classmethod
    def tearDownClass(cls): cls.build_dir.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.write('baseline', target='Eastern Standard Time', worker_sha256=hashlib.sha256(self.exe.read_bytes()).hexdigest())
        self.write('clock', timezone='China Standard Time', at_epoch=1793400000)

    def write(self, name, **values):
        (self.root / (name + '.ini')).write_text('[guard]\n' + ''.join(str(k) + '=' + str(v) + '\n' for k, v in values.items()), encoding='ascii')

    def read(self, name):
        value=configparser.ConfigParser();value.read(self.root/(name+'.ini'));return dict(value['guard'])

    def run_worker(self):
        return subprocess.run([str(self.exe), '--once', str(self.root)], capture_output=True, timeout=10).returncode

    def test_drift_readback_then_healthy_cycle_without_real_timezone_change(self):
        tzutil = str(Path(os.environ['SystemRoot'])/'System32/tzutil.exe')
        before = subprocess.check_output([tzutil, '/g'])
        self.assertEqual(self.run_worker(), 0)
        self.assertEqual(self.read('status')['state'], 'restored')
        self.assertEqual(self.read('clock')['timezone'], 'Eastern Standard Time')
        self.assertEqual(self.run_worker(), 0)
        self.assertEqual(self.read('status')['state'], 'healthy')
        self.assertEqual(subprocess.check_output([tzutil, '/g']), before)
        self.assertTrue(list(self.root.glob('events-*.jsonl')))

    def test_pending_and_repeated_drift_pause_before_write(self):
        self.write('state', pending=1, state='repairing', attempts='1793399999')
        self.assertEqual(self.run_worker(), 0)
        self.assertEqual(self.read('status')['state'], 'attention')
        self.assertEqual(self.read('clock')['timezone'], 'China Standard Time')
        self.write('state', pending=0, state='healthy', attempts='1793398000,1793398600,1793399200')
        self.assertEqual(self.run_worker(), 0)
        self.assertEqual(self.read('status')['state'], 'paused')
        self.assertEqual(self.read('clock')['timezone'], 'China Standard Time')

    def test_tampered_identity_and_invalid_target_cannot_write(self):
        for values in ({'target':'Eastern Standard Time','worker_sha256':'0'*64}, {'target':'bad\"; command','worker_sha256':hashlib.sha256(self.exe.read_bytes()).hexdigest()}):
            self.write('baseline', **values)
            self.assertNotEqual(self.run_worker(), 0)
            self.assertEqual(self.read('clock')['timezone'], 'China Standard Time')

    def test_malformed_pending_marker_never_allows_a_write(self):
        self.write('state',pending='unknown',state='repairing',attempts='')
        self.assertNotEqual(self.run_worker(),0)
        self.assertEqual(self.read('clock')['timezone'],'China Standard Time')
