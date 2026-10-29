"""Whole client transactions against disposable preferences and fake processes."""
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock,patch

from envscope.client_config import tun_model
from envscope.client_repair import ClientRepair,NativeClientIO
from envscope.discovery import config_directories
from envscope.state import StateStore
from envscope.target_environment import fingerprint


class Interrupted(BaseException):pass


class ClientFixture(NativeClientIO):
    def __init__(self,home,system='Windows'):
        self.directory=config_directories(home,system,{})[0];self.directory.mkdir(parents=True)
        self.preference=self.directory/'verge.yaml'
        self.preference.write_bytes(b'# user comment\nenable_tun_mode: false # preserve\nlanguage: "zh-CN"\n')
        (self.directory/'clash-verge.yaml').write_bytes(b'external-controller: 127.0.0.1:9090\nsecret: "fixture-only-token"\n')
        (self.directory/'profiles.yaml').write_bytes(b'current: fixture-profile\n')
        self.binary=home/('Clash Verge/clash-verge.exe' if system=='Windows' else 'Clash Verge.app/Contents/MacOS/clash-verge')
        self.binary.parent.mkdir(parents=True);self.binary.write_bytes(b'NEVER_EXECUTE_PROXY_FIXTURE')
        self.app={'id':'fixture-proxy','mode':'clash-verge','label':'Clash Verge','path':str(self.binary),
                  'bundle':None if system=='Windows' else str(home/'Clash Verge.app')}
        self.running=True;self.born=1000.25;self.unreadable=False
        self.desktop_closed=True;self.decline=False;self.bad=False;self.flush=False;self.crash=False;self.calls=[]
        super().__init__(home,system,{},apps=lambda:[self.app],life=object(),stop_desktop=lambda:True,
                         inventory=lambda:{},facts=lambda:{})
    def actor(self):return 'fixture-owner'
    def snapshot(self,app):return {'processes':[{'pid':7,'created':self.born,'exe':str(self.binary),'owner':'fixture-owner'}] if self.running else [],'unreadable':self.unreadable}
    def close_desktop(self):self.calls.append(('close-desktop',));return self.desktop_closed
    def stop(self,app,allow_force=False):
        self.calls.append(('stop-proxy',allow_force))
        if self.decline and not allow_force:return {'stopped':False,'forced':False}
        self.running=False
        if self.flush:
            self.preference.write_bytes(self.preference.read_bytes()+b'new_after_exit: keep\n');self.flush=False
        return {'stopped':True,'forced':self.decline and allow_force}
    def start(self,app):
        self.calls.append(('start-proxy',));self.running=True
        if self.crash:raise Interrupted()
        return {'requested':True}
    def observe(self,app,settings,context=None):
        ready=self.running and (context is None or not self.bad and tun_model(self.preference.read_bytes())=={'present':True,'value':True})
        return {'ready':ready,'reason':'Fixture process / core / route evidence' if ready else 'Fixture route not verified',
                'scope':'fixture-process-core-and-routes' if context else 'fixture-process'}


class ClientRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name).resolve()
        self.store=StateStore(self.home/'state')
        self.store.save_settings({'usage':'desktop','connection_mode':'tun','client':'clash-verge','usage_country':'US'},confirm_environment=True)
        self.io=ClientFixture(self.home);self.seconds=0
        def sleep(n):self.seconds+=n
        self.manager=ClientRepair(self.store,self.io,clock=lambda:self.seconds,sleeper=sleep)
        self.report={'report_id':'fixture-report','created_at':datetime.now(timezone.utc).isoformat(),'mode':'one-click-desktop',
                     'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],
                     'environment':{'fingerprint':fingerprint(self.store.settings())}}

    def prepare(self,**kwargs):
        result=self.manager.prepare(self.report,tun=True,**kwargs)
        self.assertEqual(result['state'],'planned',result);return result

    def test_preview_confirmation_committed_readback_and_cross_restart_restore(self):
        original=self.io.preference.read_bytes();plan=self.prepare()
        self.assertEqual(self.io.calls,[]);self.assertFalse(self.manager.root.exists())
        for value in (False,1,'true'):
            self.assertEqual(self.manager.apply(plan['plan_id'],value)['state'],'confirmation_required')
        result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'completed');self.assertTrue(result['needs_retest'])
        self.assertEqual(tun_model(self.io.preference.read_bytes()),{'present':True,'value':True})
        self.assertIn(b'language: "zh-CN"',self.io.preference.read_bytes())
        record=self.manager._record();self.assertEqual(record['state'],'committed')
        self.assertEqual((self.manager.root/record['id']/'before.private.bin').read_bytes(),original)
        restarted=ClientRepair(self.store,self.io,clock=lambda:self.seconds,sleeper=lambda n:None)
        restore=restarted.prepare_restore();self.assertEqual(restore['state'],'planned')
        self.assertEqual(restarted.restore(restore['plan_id'],True)['state'],'completed')
        self.assertEqual(tun_model(self.io.preference.read_bytes()),{'present':True,'value':False})
        self.assertTrue(self.io.running);self.assertEqual(restarted.status()['state'],'rolled_back')

    def test_initially_stopped_state_is_restored_after_failed_verification(self):
        self.io.running=False;self.io.bad=True;plan=self.prepare()
        result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'partial');self.assertEqual(result['recovery']['state'],'completed')
        self.assertFalse(self.io.running);self.assertEqual(tun_model(self.io.preference.read_bytes())['value'],False)
        self.assertEqual(self.manager.status()['state'],'rolled_back')

    def test_normal_exit_declined_or_claude_not_closed_does_not_write(self):
        original=self.io.preference.read_bytes();self.io.decline=True;plan=self.prepare()
        result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'guided');self.assertEqual(self.io.preference.read_bytes(),original)
        self.assertTrue(self.io.running);self.assertEqual(self.manager.status()['state'],'not_applied')
        self.setUp();self.io.desktop_closed=False;plan=self.prepare()
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'guided')
        self.assertNotIn(('stop-proxy',False),self.io.calls)

    def test_explicit_proxy_force_does_not_authorize_claude_force(self):
        self.io.decline=True;plan=self.prepare(allow_force=True)
        self.assertTrue(any('不会强制退出 Claude' in e for e in plan['effects']))
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'completed')
        self.assertIn(('stop-proxy',True),self.io.calls)

    def test_preferences_flushed_on_exit_are_preserved_and_original_proxy_reopened(self):
        self.io.flush=True;plan=self.prepare();result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'partial');self.assertEqual(result['recovery']['state'],'completed')
        self.assertIn(b'new_after_exit: keep',self.io.preference.read_bytes())
        self.assertFalse(tun_model(self.io.preference.read_bytes())['value']);self.assertTrue(self.io.running)

    def test_actual_interruption_blocks_new_plan_and_preserves_later_unrelated_edits_on_recovery(self):
        plan=self.prepare();self.io.crash=True
        with self.assertRaises(Interrupted):self.manager.apply(plan['plan_id'],True)
        self.io.crash=False
        restarted=ClientRepair(self.store,self.io,clock=lambda:self.seconds,sleeper=lambda n:None)
        self.assertEqual(restarted.status()['state'],'starting')
        self.assertEqual(restarted.prepare(self.report,tun=True)['state'],'guided')
        self.io.preference.write_bytes(self.io.preference.read_bytes()+b'new_after_crash: keep\n')
        restore=restarted.prepare_restore();self.assertEqual(restore['state'],'planned')
        self.assertEqual(restarted.restore(restore['plan_id'],True)['state'],'completed')
        self.assertIn(b'new_after_crash: keep',self.io.preference.read_bytes())
        self.assertFalse(tun_model(self.io.preference.read_bytes())['value'])

    def test_external_change_after_preview_and_during_restore_never_overwrites(self):
        plan=self.prepare();self.io.preference.write_bytes(self.io.preference.read_bytes()+b'external: keep\n')
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required');self.assertEqual(self.io.calls,[])
        plan=self.prepare();self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'completed')
        restore=self.manager.prepare_restore();self.io.preference.write_bytes(self.io.preference.read_bytes()+b'newest: keep\n')
        self.assertEqual(self.manager.restore(restore['plan_id'],True)['state'],'retest_required')
        self.assertTrue(tun_model(self.io.preference.read_bytes())['value'])

    def test_wrong_user_bad_backup_new_process_and_changed_target_are_not_authorization(self):
        plan=self.prepare();self.io.born+=1
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required')
        plan=self.prepare();self.store.save_settings({'locale':'en-US'})
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required')
        self.assertEqual(self.io.calls,[])
        self.setUp();plan=self.prepare();self.manager.apply(plan['plan_id'],True)
        self.io.actor=lambda:'another-user'
        self.assertEqual(self.manager.prepare_restore()['state'],'guided')
        record=self.manager._record();path=self.manager.root/record['id']/'record.private.json'
        original=path.read_bytes();invalid={**record,'directory':['unexpected','type']};path.write_text(json.dumps(invalid))
        self.assertEqual(self.manager.status()['state'],'invalid');self.assertEqual(self.manager.prepare(self.report,tun=True)['state'],'guided')
        path.write_bytes(original);(self.manager.root/record['id']/'before.private.bin').write_bytes(b'corrupt fixture')
        self.assertEqual(self.manager.status()['state'],'invalid');self.assertFalse(self.manager.status()['can_restore'])

    def test_fresh_report_and_official_region_are_required_but_no_installer_runs(self):
        self.assertEqual(self.manager.prepare(None,tun=True)['state'],'guided')
        self.store.save_settings({'usage_country':'CN'},confirm_environment=True)
        self.report['environment']['fingerprint']=fingerprint(self.store.settings())
        self.assertEqual(self.manager.prepare(self.report,tun=True)['state'],'guided')
        self.assertEqual(self.io.calls,[])
        for value in (1,'true',None):
            with self.assertRaises(ValueError):self.manager.prepare(self.report,tun=value)

    def test_waiting_for_exit_can_expire_authority_without_writing_new_preferences(self):
        original=self.io.preference.read_bytes();plan=self.prepare()
        def delayed_close():self.seconds=91;return True
        self.io.close_desktop=delayed_close
        result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'retest_required');self.assertEqual(self.io.preference.read_bytes(),original)
        self.assertEqual(self.io.calls,[]);self.assertEqual(self.manager.status()['state'],'not_applied')

    def test_native_observer_requires_process_core_and_actual_sampled_routes(self):
        self.io.preference.write_bytes(b'enable_tun_mode: true\n')
        context=self.io.context(self.io.app)
        core=Mock();core.identity=context['controller'];core.request.side_effect=lambda path:{'meta':True} if path=='/version' else {'tun':{'enable':True}}
        self.io.inventory=lambda:{'network':{'adapters':[{'Name':'tun0','Status':'Up','ifIndex':8,'InterfaceDescription':'Wintun'}]}}
        self.io.facts=lambda:{'dns':[{'host':'claude.ai','addresses':['8.8.8.8'],'complete':True}],
                              'routes':[{'destination':'8.8.8.8','interface':'tun0','interface_index':8}]}
        with patch('envscope.client_repair.from_config',return_value=core):
            result=NativeClientIO.observe(self.io,self.io.app,self.store.settings(),context)
            self.assertTrue(result['ready'])
            self.io.facts=lambda:{'dns':[{'host':'claude.ai','addresses':['8.8.8.8'],'complete':True}],
                                  'routes':[{'destination':'8.8.8.8','interface':'Ethernet','interface_index':1}]}
            self.assertFalse(NativeClientIO.observe(self.io,self.io.app,self.store.settings(),context)['ready'])
            core.request.side_effect=lambda path:{'meta':True} if path=='/version' else {'tun':{'enable':False}}
            self.assertFalse(NativeClientIO.observe(self.io,self.io.app,self.store.settings(),context)['ready'])


if __name__=='__main__':unittest.main()
