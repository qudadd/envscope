"""Production plan/API paths with a disposable client and scheduler; no real apps."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
from functools import partial
import unittest
from unittest.mock import Mock
from urllib.request import Request,ProxyHandler,build_opener
from urllib.error import HTTPError

from envscope.accounts import AccountError
from envscope.client_repair import ClientRepair
from envscope.client_config import tun_model
from envscope.model import Finding,Status,make_report
from envscope.operations import Operations
from envscope.process_guard import ProcessGuard
from envscope.service import make_server,DesktopHandler
from envscope.state import StateStore
from scripts.environment_fixtures import fixture,fixture_policy,target
from tests.test_client_repair import ClientFixture
from tests.test_process_guard import GuardIOFixture,GuardSchedulerFixture


def client_findings(home,store,io,guard,system='Windows',browser=None):
    rows=fixture(home,store.settings(),system,browser=browser)
    ready=tun_model(io.preference.read_bytes())=={'present':True,'value':True}
    for row in rows:
        if row.id=='system.inventory' and not ready:row.evidence[0]['network']['adapters']=[]
        if row.id=='baseline.tun' and not ready:
            row.status=Status.FAIL;row.summary='隔离场景：目标隧道尚未建立'
        if row.id=='baseline.proxy' and not io.running:
            row.status=Status.FAIL;row.summary='隔离场景：所选客户端离线'
        if row.id=='baseline.guard':
            state=guard.status()
            row.status=Status.PASS if state.get('running') else Status.WARN
            row.evidence=[{'kind':'envscope-process-guard','registered':state.get('scheduler',{}).get('registered',False),
                'enabled':state.get('enabled',False),'running':state.get('running',False),'configured_mode':'clash-verge'}]
    return rows


class ClientWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name).resolve()
        self.store=StateStore(self.home/'state')
        values=target('Windows','desktop','tun',usage_country='US',client='clash-verge',protection='guarded',
                      ipv6_mode='allowlist',allowed_ipv6=['2001:4860::/32'])
        self.store.save_settings({k:v for k,v in values.items() if k!='environment_confirmed'},confirm_environment=True)
        self.io=ClientFixture(self.home);self.seconds=0
        def sleep(n):self.seconds+=n
        self.client=ClientRepair(self.store,self.io,clock=lambda:self.seconds,sleeper=sleep)
        self.guard_io,self.scheduler=GuardIOFixture(),GuardSchedulerFixture()
        self.guard_io.observation['interfaces']=[{'name':'tun0','up':True},{'name':'other-tunnel','up':True}]
        self.guard=ProcessGuard(self.store,self.home,self.guard_io,self.scheduler)
        self.ops=Operations(self.store,self.home,discoverer=lambda:[],client_repair=self.client,process_guard=self.guard,
                            environment_reader=lambda:{'platform':'Windows'})
        self.ops.legacy=Mock();self.ops.solutions.legacy=self.ops.legacy
        self.client.transaction_lock=lambda:self.ops.accounts._lock()

    def report(self):
        rows=client_findings(self.home,self.store,self.io,self.guard)
        return make_report(rows,fixture_policy(self.store.settings()),'one-click-desktop',self.store.settings())

    def test_one_stop_defers_unknown_interfaces_then_offers_native_guard_without_legacy_fix(self):
        report=self.report();plan=self.ops.solutions.prepare(report)
        self.assertTrue(plan['staged']);self.assertEqual(self.io.calls,[]);self.assertEqual(self.scheduler.calls,[])
        self.assertFalse(any('网络接口' in e or '10 秒' in e for e in plan['effects']))
        applied=self.ops.solutions.apply(plan['plan_id'],report,True)
        self.assertEqual(applied['state'],'completed');self.assertTrue(applied['next_review'])
        self.assertEqual(self.scheduler.calls,[])
        current=self.report();following=self.ops.solutions.prepare(current)
        self.assertEqual(following['state'],'planned',following)
        self.assertIn('监测网卡：tun0',str(following['effects']));self.assertNotIn('监测网卡：other-tunnel',str(following['effects']))
        self.assertEqual(self.ops.solutions.apply(following['plan_id'],current,True)['state'],'executed')
        self.assertEqual(self.guard.status()['state'],'waiting')
        self.guard.pulse();self.assertEqual(self.guard.status()['state'],'armed')
        final=self.report();self.assertEqual(next(f['status'] for f in final['findings'] if f['id']=='baseline.guard'),'pass')
        self.ops.legacy.run.assert_not_called();self.ops.legacy.capabilities.assert_not_called()

    def test_selected_network_check_does_not_authorize_a_client_restart(self):
        report=self.report();value=self.ops.solutions.prepare(report,check_ids=['target.dns'])
        self.assertEqual(value['state'],'guided');self.assertEqual(self.io.calls,[])
        self.assertFalse(self.client.plans);self.assertFalse(self.scheduler.calls)
        # Real collectors report absent cores as UNKNOWN and refused listeners
        # as WARN. A stopped, explicitly selected HTTP client is still startable.
        self.store.save_settings({'connection_mode':'http_proxy','target_proxy':'http://127.0.0.1:7897','protection':'standard','ipv6_mode':'observe'},confirm_environment=True)
        self.io.running=False;report=self.report()
        next(f for f in report['findings'] if f['id']=='baseline.proxy')['status']='unknown'
        listener=next(f for f in report['findings'] if f['id']=='extra.proxy_listener')
        listener.update(status='warn',evidence=[{'endpoint':'http://127.0.0.1:7897','tcp_accepts':False}])
        value=self.ops.solutions.prepare(report,check_ids=['extra.proxy_listener'])
        self.assertTrue(value['staged']);self.assertEqual(self.ops.solutions.apply(value['plan_id'],report,True)['state'],'completed')
        self.assertIn(('start-proxy',),self.io.calls)
        # An unrelated configured port must not start a different client.
        self.io.running=False;listener['evidence'][0]['endpoint']='http://127.0.0.1:9999';calls=list(self.io.calls)
        self.assertEqual(self.ops.solutions.prepare(report,check_ids=['extra.proxy_listener'])['state'],'guided')
        self.assertEqual(self.io.calls,calls)

    def test_individual_tun_selection_and_recovery_use_the_same_coordinator(self):
        report=self.report()
        plan=self.ops.run('inspection-plan',{'report_id':report['report_id'],'check_ids':['baseline.tun']},report=report)
        self.assertEqual(plan['state'],'planned',plan)
        self.assertEqual(self.ops.run('inspection-apply',{'plan_id':plan['plan_id']},True,report)['state'],'completed')
        restore=self.ops.run('client-restore-plan',{})
        self.assertEqual(self.ops.run('client-restore',{'plan_id':restore['plan_id']},'true')['state'],'confirmation_required')
        self.assertEqual(self.ops.run('client-restore',{'plan_id':restore['plan_id']},True)['state'],'completed')
        self.assertFalse(tun_model(self.io.preference.read_bytes())['value'])

    def test_one_stop_starts_flclash_and_keeps_tun_as_a_manual_retest_requirement(self):
        self.store.save_settings({'client':'flclash'},confirm_environment=True)
        self.io.app.update(mode='flclash',label='FlClash');self.io.running=False
        before=self.io.preference.read_bytes();report=self.report()
        plan=self.ops.solutions.prepare(report)
        self.assertEqual(plan['state'],'planned',plan)
        self.assertTrue(plan['staged']);self.assertIn('FlClash',str(plan['manual']))
        self.assertFalse(self.io.calls)
        result=self.ops.solutions.apply(plan['plan_id'],report,True)
        self.assertEqual(result['state'],'completed');self.assertTrue(result['needs_retest'])
        self.assertTrue(self.io.running);self.assertEqual(self.io.preference.read_bytes(),before)
        self.assertNotEqual(self.report()['assessment']['verdict'],'qualified_in_scope')
        self.assertFalse(self.scheduler.calls)

    def test_guard_never_guesses_between_two_target_tunnels_or_incomplete_routes(self):
        self.io.preference.write_bytes(b'enable_tun_mode: true\n')
        report=self.report();route=next(f for f in report['findings'] if f['id']=='target.tun_route')
        route['evidence'].append({'destination':'2001:4860::8888','interface':'other-tunnel'})
        self.assertEqual(self.guard.prepare_from_report(report)['state'],'guided');self.assertFalse(self.scheduler.calls)
        route['status']='unknown';self.assertEqual(self.guard.prepare_from_report(report)['state'],'guided')

    def test_account_lock_is_held_through_proxy_restart_and_verification(self):
        original=self.io.close_desktop
        def close():
            with self.assertRaises(AccountError):
                with self.ops.accounts._lock():pass
            return original()
        self.io.close_desktop=close
        plan=self.client.prepare(self.report(),tun=True)
        self.assertEqual(self.client.apply(plan['plan_id'],True)['state'],'completed')
        with self.ops.accounts._lock():pass

    def test_one_stop_migrates_legacy_before_client_and_then_reviews_new_guard(self):
        from envscope.legacy_components import ComponentMigration
        from tests.test_components import ComponentsFixture
        jobs=ComponentsFixture();self.guard_io.old_guard=True
        execute=jobs.execute
        def retire(action,payload):
            execute(action,payload);self.guard_io.old_guard=action!='retire'
        jobs.execute=retire
        self.ops.components=ComponentMigration(self.store,self.home,io=jobs,transaction_lock=lambda:self.ops.accounts._lock())
        self.ops.solutions.components=self.ops.components
        report=self.report();plan=self.ops.solutions.prepare(report)
        self.assertEqual(plan['state'],'planned');self.assertTrue(plan['staged'])
        self.assertTrue(any('保护间隔' in effect for effect in plan['effects']))
        self.assertFalse(self.io.calls or self.scheduler.calls or jobs.calls)
        self.assertEqual(self.ops.solutions.apply(plan['plan_id'],report,'true')['state'],'confirmation_required')
        result=self.ops.solutions.apply(plan['plan_id'],report,True)
        self.assertEqual(result['state'],'completed');self.assertTrue(result['next_review'])
        self.assertFalse(self.io.calls or self.scheduler.calls);self.assertEqual(len(jobs.calls),1)
        current=self.report();plan=self.ops.solutions.prepare(current)
        self.assertTrue(any('enable_tun_mode' in effect for effect in plan['effects']))
        self.assertEqual(self.ops.solutions.apply(plan['plan_id'],current,True)['state'],'completed')
        current=self.report();plan=self.ops.solutions.prepare(current)
        self.assertTrue(any('监测网卡' in effect for effect in plan['effects']))
        self.assertFalse(self.scheduler.calls)

    def test_explicit_test_home_does_not_discover_or_close_installed_applications(self):
        ops=Operations(self.store,self.home,discoverer=lambda:[])
        self.assertEqual(ops.run('client-options',{})['apps'],[])
        self.assertFalse(ops.client_repair.io.close_desktop())
        self.assertEqual(ops.client_repair.root,self.home/'.envscope/client-repair')
        for params in ({'path':'arbitrary.exe'},{'tun':True,'command':'cmd'}):
            with self.assertRaises(ValueError):self.ops.run('client-plan',params,report=self.report())

    def test_http_api_requires_current_report_and_invalidates_it_only_after_write(self):
        server=make_server(store=self.store,operations=self.ops,auditor=lambda *a,**k:client_findings(self.home,self.store,self.io,self.guard,browser=k.get('browser')))
        response_locks=[]
        class ObservedHandler(DesktopHandler):
            def json_response(handler,status,value):
                if handler.command=='POST' and status==200:response_locks.append(handler.server.audit_lock.locked())
                return super().json_response(status,value)
        server.RequestHandlerClass=partial(ObservedHandler,**server.RequestHandlerClass.keywords)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        opener=build_opener(ProxyHandler({}));origin='http://127.0.0.1:'+str(server.server_port)
        def post(action,params,confirmed=False):
            request=Request(origin+'/api/action',data=json.dumps({'action':action,'params':params,'confirmed':confirmed}).encode(),
                headers={'Content-Type':'application/json','Origin':origin,'X-EnvScope-Token':server.session_token})
            return json.loads(opener.open(request,timeout=5).read())
        try:
            report=self.report();server.last_raw_report=report
            self.assertEqual(post('client-plan',{'report_id':'old','tun':True})['state'],'retest_required')
            value=post('client-plan',{'report_id':report['report_id'],'app_id':'fixture-proxy','tun':True})
            self.assertEqual(value['state'],'planned');self.assertEqual(self.io.calls,[])
            self.assertEqual(post('client-apply',{'plan_id':value['plan_id']})['state'],'confirmation_required')
            self.assertEqual(server.last_raw_report['report_id'],report['report_id'])
            server.last_raw_report={**report,'report_id':'new-audit'}
            self.assertEqual(post('client-apply',{'plan_id':value['plan_id']},True)['state'],'retest_required')
            server.last_raw_report=None
            self.assertEqual(post('client-apply',{'plan_id':value['plan_id']},True)['state'],'retest_required')
            self.assertEqual(self.io.calls,[]);server.last_raw_report=report
            self.assertEqual(post('client-apply',{'plan_id':value['plan_id']},True)['state'],'completed')
            self.assertIsNone(server.last_raw_report)
            status=post('client-status',{});self.assertTrue(status['can_restore'])
            self.assertNotIn('fixture-only-token',json.dumps(status))
            self.assertTrue(response_locks);self.assertFalse(any(response_locks),'A completed response must not retain the operation lock')
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)

    def test_read_only_status_poll_does_not_take_or_release_the_mutation_lock(self):
        # This case measures HTTP lock semantics, not real OS task-query latency.
        self.ops.maintenance.status=Mock(return_value={'state':'disabled'})
        self.ops.timezone_service.status=Mock(return_value={'state':'not_applicable','supported':False})
        server=make_server(store=self.store,operations=self.ops)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        opener=build_opener(ProxyHandler({}));origin='http://127.0.0.1:'+str(server.server_port)
        server.audit_lock.acquire()
        try:
            request=Request(origin+'/api/status',headers={'X-EnvScope-Token':server.session_token})
            value=json.loads(opener.open(request,timeout=5).read())
            self.assertEqual(value['client_repair']['state'],'not_configured');self.assertIn('process_guard',value)
            self.assertNotIn('accounts',value);self.assertTrue(server.audit_lock.locked())
            self.assertFalse(self.io.calls or self.scheduler.calls)
            request=Request(origin+'/api/action',data=json.dumps({'action':'client-status','params':{},'confirmed':False}).encode(),
                headers={'Content-Type':'application/json','Origin':origin,'X-EnvScope-Token':server.session_token})
            with self.assertRaises(HTTPError) as rejected:opener.open(request,timeout=5)
            self.assertEqual(rejected.exception.code,409)
        finally:
            server.audit_lock.release();server.shutdown();server.server_close();thread.join(timeout=3)


if __name__=='__main__':unittest.main()
