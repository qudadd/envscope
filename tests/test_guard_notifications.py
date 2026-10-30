import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock
from envscope.state import StateStore
from envscope.guard_notifications import GuardNotifications


class GuardNotificationTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.store=StateStore(Path(self.folder.name))
    def test_unchanged_failure_is_quiet_across_restart_and_recovery_rearms(self):
        store=self.store;sink=Mock();notifier=GuardNotifications(store,sink)
        bad={'enabled':True,'state':'attention','watchdog':{'proxy':{'state':'attention','note':'PRIVATE_PROXY_NAME'}}}
        self.assertTrue(notifier.update(bad,{}));self.assertFalse(notifier.update(bad,{}))
        self.assertFalse(GuardNotifications(store,sink).update(bad,{}));self.assertEqual(sink.call_count,1)
        self.assertNotIn('PRIVATE_PROXY_NAME',str(sink.call_args))
        self.assertFalse(notifier.update({'enabled':True,'state':'active'},{}))
        self.assertTrue(notifier.update(bad,{}));self.assertEqual(sink.call_count,2)

    def test_unconfigured_waiting_and_cooldown_states_do_not_notify(self):
        sink=Mock();notifier=GuardNotifications(self.store,sink)
        for state in ('disabled','waiting','active'):
            self.assertFalse(notifier.update({'enabled':state!='disabled','state':state}, {'state':'not_installed'}))
        self.assertFalse(notifier.update({'enabled':True,'state':'attention','watchdog':{'timezone':{'state':'cooldown'}}},{}))
        sink.assert_not_called()

    def test_disabled_or_unreadable_previously_approved_native_task_notifies(self):
        sink=Mock();notifier=GuardNotifications(self.store,sink)
        notifier.update({}, {'installed':True,'state':'active'})
        self.assertTrue(notifier.update({}, {'state':'attention'}))
        self.assertEqual(sink.call_args.args[0]['components'],['timezone'])

    def test_lost_heartbeat_and_unexpected_removal_need_attention(self):
        sink=Mock();now=[1000];notifier=GuardNotifications(self.store,sink,clock=lambda:now[0])
        self.assertFalse(notifier.update({}, {'installed':True,'state':'waiting'}))
        now[0]+=181
        self.assertTrue(notifier.update({}, {'installed':True,'state':'waiting'}))
        self.assertFalse(notifier.update({}, {'installed':True,'state':'waiting'}))
        self.assertTrue(notifier.update({}, {'installed':False,'state':'not_installed'}))
        notifier.update({}, {'installed':False,'state':'not_installed','intentionally_removed':True})
        self.assertFalse(notifier.active)
