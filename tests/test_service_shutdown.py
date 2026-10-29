"""Closing the owned loopback fixture waits for accepted writes and rejects new ones."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore


class ServiceShutdownTests(unittest.TestCase):
    def setup_fixture(self, home):
        store=StateStore(home/'state');ops=Operations(store,home,discoverer=lambda:[])
        server=make_server(store=store,operations=ops,auditor=Mock(return_value=[]))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        origin='http://127.0.0.1:'+str(server.server_port)
        opener=build_opener(ProxyHandler({}))
        request=Request(origin+'/api/action',json.dumps({'action':'cli-info','params':{},'confirmed':False}).encode(),
                        headers={'Origin':origin,'Content-Type':'application/json','X-EnvScope-Token':server.session_token})
        return store,ops,server,thread,opener,request

    def test_server_close_drains_operation_including_final_diagnostic_write(self):
        with tempfile.TemporaryDirectory(prefix='envscope-shutdown-') as directory:
            home=Path(directory).resolve();store,ops,server,thread,opener,request=self.setup_fixture(home)
            entered,release,closed=threading.Event(),threading.Event(),threading.Event();response=[];errors=[]
            def action(*args,**kwargs):
                entered.set()
                if not release.wait(4):raise ValueError('fixture deadline')
                return {'state':'completed'}
            ops._run=Mock(side_effect=action)
            def client():
                try:response.append(json.loads(opener.open(request,timeout=6).read()))
                except Exception as error:errors.append(type(error).__name__)
            requester=threading.Thread(target=client);requester.start()
            try:
                self.assertTrue(entered.wait(3))
                server.shutdown();thread.join(3)
                closer=threading.Thread(target=lambda:(server.server_close(),closed.set()));closer.start()
                self.assertFalse(closed.wait(.05))
                release.set();self.assertTrue(closed.wait(3))
                closer.join(3);requester.join(3)
                self.assertFalse(errors);self.assertEqual(response,[{'state':'completed'}])
                self.assertEqual(ops.diagnostics.entries()[-1]['command'],'cli-info')
                self.assertEqual(ops.diagnostics.entries()[-1]['state'],'completed')
            finally:
                release.set();server.shutdown();server.server_close();thread.join(3);requester.join(3)

    def test_stopping_service_rejects_new_reads_and_actions_without_running_them(self):
        with tempfile.TemporaryDirectory(prefix='envscope-stopping-') as directory:
            home=Path(directory).resolve();store,ops,server,thread,opener,request=self.setup_fixture(home)
            ops._run=Mock();server.closing=True
            try:
                for item in (request,request.full_url.replace('/api/action','/api/session')):
                    with self.assertRaises(HTTPError) as caught:opener.open(item,timeout=3)
                    self.assertEqual(caught.exception.code,503)
                ops._run.assert_not_called();self.assertFalse((store.root/'diagnostics').exists())
            finally:server.shutdown();server.server_close();thread.join(3)
