"""Production HTTP actions over loopback with owned data; no OS job writes."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError

from envscope.accounts import AccountError
from envscope.legacy_components import ComponentMigration
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore
from tests.test_components import ComponentsFixture


class ComponentsIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve(); self.store = StateStore(self.home/'state')
        self.io = ComponentsFixture(); self.subject = ComponentMigration(self.store, self.home, io=self.io)
        self.ops = Operations(self.store, self.home, components=self.subject, discoverer=lambda: [])
        self.ops.timezone_service.status = Mock(return_value={'state':'not_applicable','supported':False})
        self.ops.maintenance.status = Mock(return_value={'state':'disabled','enabled':False})
        self.subject.transaction_lock = lambda: self.ops.accounts._lock()
        self.server = make_server(store=self.store, operations=self.ops)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.stop)
        self.origin = 'http://127.0.0.1:'+str(self.server.server_port); self.opener = build_opener(ProxyHandler({}))

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)

    def post(self, action, params=None, confirmed=False):
        request = Request(self.origin+'/api/action', data=json.dumps({'action': action, 'params': params or {}, 'confirmed': confirmed}).encode(),
                          headers={'Content-Type':'application/json','Origin':self.origin,'X-EnvScope-Token':self.server.session_token})
        return json.loads(self.opener.open(request, timeout=5).read())

    def test_review_confirm_lock_readback_and_report_invalidation(self):
        self.server.last_raw_report = {'report_id':'fixture-report'}
        plan = self.post('components-plan', {'roles':['guard']})
        self.assertEqual(plan['state'],'planned'); self.assertFalse(self.io.calls)
        self.assertEqual(self.post('components-apply',{'plan_id':plan['plan_id']})['state'],'confirmation_required')
        self.assertIsNotNone(self.server.last_raw_report)
        execute = self.io.execute
        def locked(*args):
            with self.assertRaises(AccountError):
                with self.ops.accounts._lock(): pass
            return execute(*args)
        self.io.execute = locked
        value = self.post('components-apply',{'plan_id':plan['plan_id']},True)
        self.assertEqual(value['state'],'completed'); self.assertTrue(value['needs_retest']); self.assertIsNone(self.server.last_raw_report)
        status = self.post('components-status'); self.assertTrue(status['can_restore'])
        public = json.dumps(status)
        self.assertNotIn('fixture definition',public); self.assertNotIn('security',public); self.assertNotIn('"definition"',public)
        plan = self.post('components-plan',{'restore':True})
        self.assertEqual(self.post('components-apply',{'plan_id':plan['plan_id']},True)['state'],'restored')
        with self.ops.accounts._lock(): pass

    def test_invalid_scopes_restore_flags_and_missing_confirmation_never_write(self):
        for params in ({'restore':'true'},{'roles':['guard','guard']},{'roles':['foreign']},{'roles':['guard'],'command':'anything'}):
            with self.assertRaises(HTTPError) as error: self.post('components-plan',params)
            self.assertEqual(error.exception.code,400)
        self.assertFalse(self.io.calls)
        self.assertEqual(self.post('components-apply',{'plan_id':'missing'},True)['state'],'retest_required')
        isolated = Operations(self.store,self.home,discoverer=lambda:[])
        self.assertEqual(isolated.run('components-status',{})['state'],'unavailable')

    def test_readonly_poll_keeps_operation_lock_and_does_not_invent_measurements(self):
        self.server.audit_lock.acquire()
        try:
            request = Request(self.origin+'/api/status',headers={'X-EnvScope-Token':self.server.session_token})
            value = json.loads(self.opener.open(request,timeout=5).read())
            self.assertEqual(value['legacy_components']['state'],'not_checked')
            self.assertTrue(self.server.audit_lock.locked()); self.assertFalse(self.io.calls)
        finally: self.server.audit_lock.release()


if __name__=='__main__': unittest.main()
