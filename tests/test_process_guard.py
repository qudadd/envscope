"""Temporary state, injected adapters; never signal a real Claude process."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from envscope.process_guard import ProcessGuard, NativeGuardIO, desktop_path, health
from envscope.scheduler import UserScheduler, windows_xml, windows_identity, mac_plist, ROLES
from envscope.state import StateStore
from envscope.baseline import guard_finding
from envscope.model import Status
from scripts.environment_fixtures import report, target
from tests.test_maintenance import FakeScheduler


class GuardSchedulerFixture(FakeScheduler):
    def start(self, spec):
        self.calls.append(('start', spec))
        if self.fail:
            raise ValueError('fixture cannot start')


class GuardIOFixture:
    def __init__(self):
        self.online, self.live, self.stop_ok = True, True, True
        self.old_guard = False
        self.stops = []
        self.observation = {'targets': [], 'unreadable': False, 'clients': ['mihomo'], 'interfaces': [{'name': 'utun9', 'up': True}]}
    def snapshot(self):
        return deepcopy(self.observation)
    def legacy(self):
        return {'rows': [{'id': 'guard', 'present': self.old_guard, 'registered': self.old_guard}]}
    def identity(self):
        return {'pid': 12345, 'created': 1.0, 'exe': 'fixture-not-running'}
    def alive(self, *args):
        return self.live
    def listening(self, url):
        return self.online
    def stop(self, targets):
        self.stops.append(targets)
        if self.stop_ok:
            self.observation['targets'] = []
        return self.stop_ok


class ProcessGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.store = StateStore(self.home/'state')
        settings = target('Windows', 'desktop', 'http_proxy', usage_country='US', country='US', target_proxy='http://127.0.0.1:7897')
        self.store.save_settings({k: v for k, v in settings.items() if k != 'environment_confirmed'}, confirm_environment=True)
        self.report = report(self.home, self.store.settings(), 'Windows')
        self.io, self.scheduler = GuardIOFixture(), GuardSchedulerFixture()
        self.guard = ProcessGuard(self.store, self.home, self.io, self.scheduler)

    def enable(self):
        plan = self.guard.prepare(self.report)
        self.assertEqual(plan['state'], 'planned', plan)
        self.assertEqual(self.guard.enable(plan['plan_id'], self.report, True)['state'], 'enabled')
        return plan

    def test_preview_does_not_write_and_approval_waits_for_real_heartbeat(self):
        self.assertFalse(self.guard.root.exists())
        plan = self.guard.prepare(self.report)
        self.assertFalse(self.guard.root.exists()); self.assertFalse(self.scheduler.calls)
        self.assertEqual(self.guard.enable(plan['plan_id'], self.report, 'true')['state'], 'confirmation_required')
        self.assertEqual(self.guard.enable(plan['plan_id'], self.report, True)['state'], 'enabled')
        self.assertEqual(self.guard.status()['state'], 'waiting')
        self.guard.pulse(); self.assertEqual(self.guard.status()['state'], 'armed')
        self.assertTrue(self.guard.status()['running']); self.assertFalse(self.io.stops)

    def test_proxy_offline_stops_once_records_intent_and_requires_manual_relaunch(self):
        self.enable(); self.io.observation['targets'] = [{'pid': 77, 'created': 3.0, 'exe': 'fixture'}]
        self.io.online = False
        self.assertEqual(self.guard.pulse()['state'], 'blocked')
        self.assertEqual(len(self.io.stops), 1)
        self.guard.pulse(); self.assertEqual(len(self.io.stops), 1)
        rows = self.guard.read('events', {})['rows']
        phases = [v['kind'] for v in rows]
        self.assertLess(phases.index('stop_requested'), phases.index('stopped'))
        self.assertTrue(list((self.guard.root/'events').glob('*.private.jsonl')))
        self.io.online = True; self.guard.pulse()
        self.assertFalse(self.io.observation['targets'])
        self.assertEqual(self.guard.status()['state'], 'armed')

    def test_readback_or_permission_failure_never_claims_exit(self):
        self.enable(); self.io.online = False; self.io.stop_ok = False
        self.io.observation['targets'] = [{'pid': 1}]
        self.assertEqual(self.guard.pulse()['state'], 'attention')
        self.assertFalse(self.guard.status()['running'])
        self.io.observation.update(targets=[], unreadable=True)
        self.assertEqual(self.guard.pulse()['state'], 'attention')

    def test_settings_change_pauses_before_signal_and_invalidates_preview(self):
        plan = self.guard.prepare(self.report)
        self.store.save_settings({'target_proxy': 'http://127.0.0.1:7898'})
        self.assertEqual(self.guard.enable(plan['plan_id'], self.report, True)['state'], 'retest_required')
        self.store.save_settings({'target_proxy': 'http://127.0.0.1:7897'}, confirm_environment=True)
        self.report = report(self.home, self.store.settings(), 'Windows'); self.enable()
        self.store.save_settings({'locale': 'en-GB'})
        self.io.online = False; self.io.observation['targets'] = [{'pid': 77}]
        self.assertEqual(self.guard.pulse()['state'], 'paused'); self.assertFalse(self.io.stops)
        self.assertFalse(self.guard.status()['running'])

    def test_dead_worker_or_stale_timestamp_or_changed_task_never_passes(self):
        self.enable(); self.guard.pulse()
        self.io.live = False; self.assertEqual(self.guard.status()['state'], 'stale')
        self.io.live = True
        value = self.guard.read('pulse', {}); value['at'] = (datetime.now(timezone.utc)-timedelta(seconds=31)).isoformat()
        self.guard.write('pulse', value); self.assertFalse(self.guard.status()['running'])
        self.guard.pulse(); self.scheduler.definition = {'body': 'foreign'}
        self.assertEqual(self.guard.status()['state'], 'schedule_unverified')

    def test_software_directory_change_requires_new_schedule(self):
        self.enable(); self.guard.pulse()
        self.scheduler.command = ['new fixture executable']
        self.assertEqual(self.guard.status()['state'], 'outdated')
        self.assertFalse(self.guard.status()['running'])

    def test_disable_prevents_every_later_signal_even_if_task_removal_fails(self):
        self.enable(); self.scheduler.fail = True
        self.assertEqual(self.guard.disable(True)['state'], 'partial')
        self.io.online = False; self.io.observation['targets'] = [{'pid': 77}]
        self.assertEqual(self.guard.pulse()['state'], 'disabled'); self.assertFalse(self.io.stops)

    def test_failed_registration_does_not_enable(self):
        plan = self.guard.prepare(self.report); self.scheduler.fail = True
        self.assertEqual(self.guard.enable(plan['plan_id'], self.report, True)['state'], 'failed')
        self.assertEqual(self.guard.pulse()['state'], 'disabled')

    def test_region_failure_and_direct_or_web_usage_cannot_enable(self):
        r = deepcopy(self.report)
        next(f for f in r['findings'] if f['id'] == 'target.region')['status'] = 'fail'
        self.assertEqual(self.guard.prepare(r)['state'], 'retest_required')
        for usage, mode in [('desktop','direct'), ('web','http_proxy'), ('cli','http_proxy')]:
            settings = target('Windows', usage, mode, usage_country='US', country='US')
            self.store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
            r = report(self.home, self.store.settings(), 'Windows')
            self.assertEqual(self.guard.prepare(r)['state'], 'blocked')

    def test_exact_selected_tun_and_kernel_are_both_required(self):
        baseline = {'mode':'tun','proxy':'','interface':'utun9','client':'clash-verge'}
        self.assertTrue(health(baseline, self.io.snapshot(), self.io)[0])
        self.io.observation['interfaces'] = [{'name':'utun8','up':True}]
        self.assertFalse(health(baseline, self.io.snapshot(), self.io)[0])
        self.io.observation['interfaces'] = [{'name':'utun9','up':True}]; self.io.observation['clients'] = []
        self.assertFalse(health(baseline, self.io.snapshot(), self.io)[0])
        self.io.observation['interfaces'] = None
        self.assertIn('读取失败', health(baseline, self.io.snapshot(), self.io)[1])

    def test_worker_polls_and_exits_after_disable_and_refuses_duplicate(self):
        self.enable(); waits = []
        def sleep(seconds):
            waits.append(seconds)
            self.guard.disable(True)
        self.assertEqual(self.guard.work(sleep), 0)
        self.assertEqual(len(waits), 1); self.assertLessEqual(waits[0], 10)
        with self.guard.lock('worker'):
            with self.assertRaises(ValueError):
                self.guard.work(lambda _: None)

    def test_native_guard_report_needs_verified_current_evidence(self):
        value = {'kind':'envscope-process-guard','registered':True,'enabled':True,'running':False,'configured_mode':'auto'}
        self.assertEqual(guard_finding(value, {}).status, Status.UNKNOWN)
        value['running'] = True
        self.assertEqual(guard_finding(value, {}).status, Status.PASS)
        self.assertEqual(guard_finding(value, {'client':'surge'}).status, Status.FAIL)

    def test_private_event_rotation_preserves_complete_journal(self):
        for i in range(110): self.guard.event('fixture', str(i))
        self.assertEqual(len(self.guard.read('events', {})['rows']), 100)
        logs = list((self.guard.root/'events').glob('*.private.jsonl'))
        self.assertEqual(sum(len(p.read_text().splitlines()) for p in logs), 110)


class ProcessGuardNativeTests(unittest.TestCase):
    def test_desktop_paths_exclude_code_and_other_installations(self):
        home = 'C:/Users/example'
        self.assertTrue(desktop_path(home+'/AppData/Local/Programs/Claude/app-1/Claude.exe',home,'Windows'))
        self.assertFalse(desktop_path(home+'/.local/bin/claude.exe',home,'Windows'))
        self.assertFalse(desktop_path('C:/other/Claude/claude.exe',home,'Windows'))
        self.assertFalse(desktop_path(home+'/AppData/Local/Programs/Claude/../bad/claude.exe',home,'Windows'))
        self.assertTrue(desktop_path('/Applications/Claude.app/Contents/MacOS/Claude','/Users/x','Darwin'))
        self.assertFalse(desktop_path('/usr/local/bin/claude','/Users/x','Darwin'))

    def test_actual_psutil_pid_reuse_gate_and_owned_fixture_stop(self):
        import psutil
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            p = psutil.Process(child.pid)
            item = {'pid':p.pid,'created':p.create_time(),'exe':p.exe()}
            io = NativeGuardIO(Path.home())
            self.assertFalse(io.stop([item]))  # An ordinary Python is never Claude.
            self.assertIsNone(child.poll())
            with patch('envscope.process_guard.desktop_path', return_value=True):
                self.assertFalse(io.stop([{**item,'created':item['created']-1}]))
                self.assertIsNone(child.poll())
                self.assertTrue(io.stop([item]))  # Only the test's own child.
            child.wait(timeout=5)
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=5)

    def test_resident_schedule_is_separate_and_never_elevates(self):
        xml = windows_xml(['C:/fixture/EnvScope.exe','--process-guard-worker'],'C:/fixture',5,'S-1-5-21-123',role='guard')
        identity = windows_identity(xml)
        self.assertEqual(identity['marker'], ROLES['guard'][2]); self.assertEqual(identity['execution_limit'],'PT0S')
        self.assertEqual(identity['level'],'LeastPrivilege')
        plist = plistlib.loads(mac_plist(['/fixture/EnvScope','--process-guard-worker'],'/fixture',5,role='guard'))
        self.assertEqual(plist['Label'],'org.envscope.process-guard'); self.assertNotIn('UserName',plist)
        with tempfile.TemporaryDirectory() as directory:
            s = UserScheduler(Path(directory).resolve(),Path(directory).resolve()/'guard',system='Darwin',role='guard',uid=501)
            self.assertIn('LaunchAgents',str(s.path)); self.assertIn('process-guard',s.path.name)


if __name__ == '__main__': unittest.main()
