from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from envscope.watchdog import Watchdog, native_write
from envscope.maintenance import Maintenance
from envscope.state import StateStore
from envscope.accounts import AccountManager, AccountError
from tests.test_maintenance import FakeScheduler
from scripts.environment_fixtures import report, target


class WatchdogTests(unittest.TestCase):
    def test_authorized_mac_service_owns_timezone_repairs_without_duplicate_writes(self):
        from datetime import datetime,timezone
        now=datetime.now(timezone.utc).timestamp()
        writer=Mock()
        authority=lambda:{'registered':True,'pending':False,'baseline':{'target':'America/New_York'},
                          'status':{'at_epoch':now,'state':'healthy','initial':False}}
        guard=Watchdog(system='Darwin',reader=lambda:{'timezone_iana':'Asia/Shanghai'},writer=writer,authority=authority)
        stats={};events=[]
        self.assertFalse(guard.run({'timezone':'America/New_York'},stats,lambda *a,**k:events.append(a),lambda:None))
        self.assertEqual(stats['watchdog']['timezone']['state'],'delegated')
        self.assertEqual(stats['watchdog']['timezone']['attempts'],[])
        writer.assert_not_called()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name).resolve();self.events=[];self.writes=[];self.persisted=[]
        self.inventory={'network':{'timezone_id':'Eastern Standard Time'},'locale':'en-US'}
        def write(key,value):
            self.assertTrue(any(e[0]=='watchdog_drift' for e in self.events))
            self.writes.append((key,value))
            if key=='timezone':self.inventory['network']['timezone_id']=value
            else:self.inventory['locale']=value
        self.guard=Watchdog(self.home,'Windows',reader=lambda:self.inventory,writer=write,clients=lambda:[])
        self.stats={}
    def run_guard(self,baseline):
        return self.guard.run(baseline,self.stats,lambda kind,text,**extra:self.events.append((kind,text,extra)),lambda:self.persisted.append(json.loads(json.dumps(self.stats))))

    def test_timezone_and_locale_drift_recover_and_leave_intent_before_write(self):
        self.inventory['network']['timezone_id']='China Standard Time';self.inventory['locale']='zh-CN'
        self.assertTrue(self.run_guard({'timezone':'Eastern Standard Time','locale':'en-US'}))
        self.assertEqual(len(self.writes),2)
        self.assertTrue(self.persisted[0]['watchdog']['timezone']['pending'])
        self.assertFalse(self.stats['watchdog']['timezone']['pending'])
        self.assertFalse(self.run_guard({'timezone':'Eastern Standard Time','locale':'en-US'}))
        self.assertEqual(len(self.writes),2)

    def test_failed_write_cooldown_and_crash_record_never_claim_success(self):
        self.inventory['network']['timezone_id']='wrong'
        self.guard.writer=lambda *args:None
        self.assertTrue(self.run_guard({'timezone':'Eastern Standard Time'}))
        self.assertEqual(self.stats['watchdog']['timezone']['state'],'attention')
        self.run_guard({'timezone':'Eastern Standard Time'})
        self.assertEqual(self.stats['watchdog']['timezone']['state'],'cooldown')
        self.stats['watchdog']['timezone']['pending']=True
        self.run_guard({'timezone':'Eastern Standard Time'})
        self.assertIn('上轮',self.stats['watchdog']['timezone']['note'])

    def test_repeated_drift_pauses_without_more_writes(self):
        now=datetime.now(timezone.utc).timestamp()
        self.stats={'watchdog':{'timezone':{'attempts':[now-1800,now-1200,now-600]}}}
        self.inventory['network']['timezone_id']='wrong'
        self.run_guard({'timezone':'Eastern Standard Time'})
        self.assertEqual(self.stats['watchdog']['timezone']['state'],'paused');self.assertFalse(self.writes)

    def test_proxy_offline_reopens_only_approved_binary_and_rechecks(self):
        exe=self.home/'approved-fixture.exe';exe.write_bytes(b'not a real executable')
        client={'id':'fixture','path':str(exe),'label':'Fixture'};online=[True];launches=[]
        self.guard.clients=lambda:[client];self.guard.listener=lambda url:online[0];self.guard.tester=lambda url:online[0]
        self.guard.controller=lambda:(_ for _ in ()).throw(ValueError('No fixture controller'))
        self.guard.launcher=lambda c:(launches.append(c),online.__setitem__(0,True))
        baseline,_=self.guard.prepare({'target_proxy':'http://127.0.0.1:7897'},{'proxy':True,'client':'fixture'})
        self.guard.validate(baseline);online[0]=False
        self.assertTrue(self.run_guard(baseline));self.assertEqual(len(launches),1)
        self.assertEqual(self.stats['watchdog']['proxy']['state'],'restored')

    def test_live_proxy_upstream_failure_does_not_restart_or_go_direct(self):
        self.guard.listener=lambda url:True;self.guard.tester=lambda url:False
        self.guard.launcher=lambda c:self.fail('Must not restart a running proxy')
        self.run_guard({'proxy':{'url':'http://127.0.0.1:7897'}})
        self.assertEqual(self.stats['watchdog']['proxy']['state'],'attention')

    def test_node_rollback_after_failed_tls_check(self):
        class Controller:
            identity='fixture';now='old';calls=[]
            def groups(self):return [{'name':'group','now':self.now,'nodes':['old','approved']}]
            def select(self,group,node,expected,restore=False):
                assert self.now==expected
                self.calls.append((node,restore));self.now=node
        c=Controller();self.guard.controller=lambda:c;self.guard.listener=lambda url:True
        self.guard.tester=lambda url:c.now=='old'
        self.run_guard({'proxy':{'url':'http://127.0.0.1:7897','group':'group','node':'approved','identity':'fixture'}})
        self.assertEqual(c.calls,[('approved',False),('old',True)]);self.assertEqual(c.now,'old')
        self.assertEqual(self.stats['watchdog']['proxy']['state'],'attention')

    def test_native_background_timezone_never_invokes_elevation(self):
        commands=[]
        class Denied:returncode=1
        def runner(command,**kwargs):commands.append(command);return Denied()
        for system,value in [('Windows','Eastern Standard Time'),('Darwin','America/New_York')]:
            with self.assertRaises(ValueError):native_write('timezone',value,system,runner)
        self.assertEqual(len(commands),2)
        self.assertNotIn('osascript',str(commands));self.assertNotIn('RunAs',str(commands))

    def test_maintenance_baseline_recheck_and_durable_log_survive_ui_rotation(self):
        store=StateStore(self.home/'state')
        settings=target('Windows','desktop','direct',region_profile='us-new-york',country='US',usage_country='US',timezone='Eastern Standard Time',locale='en-US')
        store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
        manager=Maintenance(store,home=self.home,scheduler=FakeScheduler(),watchdog=self.guard)
        r=report(self.home,store.settings(),'Windows')
        plan=manager.prepare(r,5,False,{'timezone':True})
        self.assertEqual(plan['state'],'planned')
        self.inventory['network']['timezone_id']='changed after preview'
        self.assertEqual(manager.enable(plan['plan_id'],r,True)['state'],'retest_required')
        for i in range(110):manager._event('fixture','event '+str(i))
        self.assertEqual(len(manager._read('events',[])),100)
        logs=list((manager.root/'events').glob('*.jsonl'))
        self.assertEqual(len(logs),1)
        self.assertEqual(len(logs[0].read_text(encoding='utf-8').splitlines()),110)


class IdentityIsolationTests(unittest.TestCase):
    def test_repeated_switches_preserve_each_accounts_device_and_oauth_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();state=root/'state';data=root/'Claude';b=state/'accounts/B'
            data.mkdir();b.mkdir(parents=True);(state/'current.txt').write_text('A')
            items={'Local State':b'fixture-device-','Local Storage/leveldb/state':b'fixture-oauth-','Cookies':b'fixture-cookie-'}
            for folder,tag in [(data,b'A'),(b,b'B')]:
                for name,prefix in items.items():
                    file=folder/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(prefix+tag)
            manager=AccountManager(state,data,'current.txt',lambda:True,lambda:True)
            for slot in ('B','A','B','A'):
                manager.switch(slot,lambda:True)
                for name,prefix in items.items():self.assertEqual((data/name).read_bytes(),prefix+slot.encode())
            events=[json.loads(line) for p in (state/'account-events').glob('*.jsonl') for line in p.read_text().splitlines()]
            self.assertEqual(sum(e['phase']=='committed' for e in events),4)
            self.assertNotIn('fixture-oauth',json.dumps(events))
            for path in ('Cookies','Local State','Local Storage/','settings.json'):
                manager.keep_file.write_text(path)
                with self.assertRaises(AccountError):manager.switch('B',lambda:True)
                self.assertEqual((data/'Cookies').read_bytes(),b'fixture-cookie-A')


if __name__=='__main__':unittest.main()
