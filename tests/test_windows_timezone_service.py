import copy
import hashlib
import tempfile
import time
import unittest
import subprocess
import platform
from pathlib import Path

from envscope import __release__
from envscope.consent import ConsentError
from envscope.state import StateStore
from envscope.timezone_windows import WindowsTimezoneService, WindowsTimezoneIO, stable, installer_bootstrap
from scripts.environment_fixtures import report, target


class WindowsTimezoneFixture:
    fixture=True
    clock=staticmethod(time.time)
    def __init__(self,inventory):
        self.inventory=inventory;self.value={'baseline':{},'status':{},'transaction':{},'registered':False,'enabled':False,'pending':False,'baseline_sha':'','worker_sha':''}
        self.backups={};self.cancel=False;self.interrupt=False;self.worker_hash='a'*64
    def inspect(self):return copy.deepcopy(self.value)
    def owner(self):return 'S-1-5-21-1-2-3-1001'
    def worker(self):return {'path':'C:/fixture/worker.exe','sha256':self.worker_hash,'release':__release__}
    def execute(self,payload):
        if self.cancel:raise ConsentError('consent_cancelled')
        action=payload['action']
        if action=='restore':
            old,zone=self.backups[payload['restore_id']];self.value=copy.deepcopy(old);self.inventory['network']['timezone_id']=zone
            self.value['transaction']={'id':payload['restore_id'],'owner':self.owner(),'state':'restored'};return
        nonce=payload['nonce'];self.backups[nonce]=(self.inspect(),self.inventory['network']['timezone_id'])
        self.value['transaction']={'id':nonce,'owner':self.owner(),'state':'pending','before_zone':payload['observed']}
        if self.interrupt:self.value['pending']=True;raise ValueError('fixture interruption')
        if action=='install':
            self.value.update(baseline={'target':payload['target'],'original':self.value['baseline'].get('original',payload['observed']),
                'owner':self.owner(),'release':__release__},registered=True,enabled=True,baseline_sha=hashlib.sha256(nonce.encode()).hexdigest(),worker_sha=self.worker_hash)
            self.inventory['network']['timezone_id']=payload['target']
            self.value['status']={'format':'1','guard_policy':'2','at_epoch':str(self.clock()),'initial':'0','fixture':'1','release':__release__,'target':payload['target'],'observed':payload['target'],'state':'healthy'}
        else:
            if payload['restore']:self.inventory['network']['timezone_id']=self.value['baseline']['original']
            self.value.update(baseline={},registered=False,enabled=False,baseline_sha='')
        self.value['transaction']['state']='committed'
        self.value['transaction'].update(after_baseline_sha=self.value['baseline_sha'],after_worker_sha=self.value['worker_sha'])


class WindowsTimezoneServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name)
        self.store=StateStore(self.home/'state');settings=target('Windows',usage_country='US',timezone='Eastern Standard Time',locale='en-US',country='US')
        self.store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
        self.report=report(self.home,self.store.settings(),'Windows')
        self.inventory={'network':{'timezone_id':'China Standard Time'}};self.io=WindowsTimezoneFixture(self.inventory)
        self.service=WindowsTimezoneService(self.store,lambda:self.inventory,io=self.io)
    def install(self):
        plan=self.service.prepare(self.report);self.assertEqual(plan['state'],'planned',plan)
        self.assertEqual(self.service.apply(plan['plan_id'],'true')['state'],'confirmation_required')
        result=self.service.apply(plan['plan_id'],True);self.assertEqual(result['state'],'completed',result);return result
    def test_install_stop_restore_and_undo_preserve_original(self):
        self.install();self.assertEqual(self.service.status()['state'],'active')
        plan=self.service.prepare(self.report,remove=True,restore=True)
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'completed')
        self.assertEqual(self.inventory['network']['timezone_id'],'China Standard Time')
        plan=self.service.prepare_undo();self.assertEqual(self.service.undo(plan['plan_id'],True)['state'],'completed')
        self.assertEqual(self.service.status()['state'],'active')
    def test_cancel_and_interruption_keep_the_correct_recovery_state(self):
        self.io.cancel=True;plan=self.service.prepare(self.report);result=self.service.apply(plan['plan_id'],True)
        self.assertEqual(result['error'],'consent_cancelled');self.assertEqual(self.service.status()['state'],'not_installed')
        self.io.cancel=False;self.io.interrupt=True;plan=self.service.prepare(self.report)
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'partial')
        self.assertEqual(self.service.status()['state'],'recovery_required')
        self.io.interrupt=False;plan=self.service.prepare_recovery();self.assertEqual(self.service.recover(plan['plan_id'],True)['state'],'completed')
        self.assertEqual(self.inventory['network']['timezone_id'],'China Standard Time')
    def test_foreign_owner_changed_binary_and_revoked_registration_are_visible(self):
        plan=self.service.prepare(self.report);self.io.worker_hash='b'*64
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'retest_required')
        self.install();self.io.value['enabled']=False
        self.assertEqual(self.service.status()['state'],'unregistered')
        self.io.value['baseline']['owner']='S-1-5-21-1-2-3-9999'
        self.assertEqual(self.service.status()['state'],'conflict')
        self.assertEqual(self.service.prepare(self.report)['state'],'blocked')
    def test_stale_heartbeat_is_not_running_and_target_change_invalidates_plan(self):
        self.install();self.io.value['status']['at_epoch']='1'
        self.assertEqual(self.service.status()['state'],'waiting')
        plan=self.service.prepare(self.report);self.store.save_settings({'timezone':'UTC'})
        self.assertEqual(self.service.apply(plan['plan_id'],True)['state'],'retest_required')


@unittest.skipUnless(platform.system()=='Windows','Windows PowerShell transport')
class WindowsTimezoneTransportTests(unittest.TestCase):
    def test_snapshot_retains_transaction_receipt_in_powershell_case_insensitive_scope(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);receipt={'id':'a'*32,'owner':'S-1-5-21-1-2-3-1001','state':'pending'}
            (root/'transaction.json').write_text(json.dumps(receipt))
            io=WindowsTimezoneIO(root=root,task='EnvScope-TimezoneFixture-12345678',fixture=True)
            value=io._read('function Assert-Protected($path){};function Read-Task{return $null};Snapshot | ConvertTo-Json -Depth 12 -Compress')
            self.assertEqual(value['transaction'],receipt)
            self.assertTrue(value['pending'])

    def test_windows_powershell_ini_parser_preserves_values_and_rejects_duplicates(self):
        import re
        from envscope.timezone_windows import HEADER
        source=re.search(r'function Ini\(\$path\) \{.*?\n\}',HEADER,re.S).group()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.ini';path.write_text('[guard]\ntimezone=Eastern Standard Time\nvalue=a=b\n')
            command=[WindowsTimezoneIO().executable,'-NoProfile','-NonInteractive','-Command',
                     'function Assert-Protected($path){};'+source+';Ini '+"'"+str(path).replace("'","''")+"'"+' | ConvertTo-Json -Compress']
            value=subprocess.run(command,capture_output=True,timeout=15)
            self.assertEqual(value.returncode,0,value.stderr)
            import json
            self.assertEqual(json.loads(value.stdout)['value'],'a=b')
            path.write_text('[guard]\nvalue=1\nvalue=2\n')
            self.assertNotEqual(subprocess.run(command,capture_output=True,timeout=15).returncode,0)

    def test_verified_source_is_snapshot_and_tamper_never_executes(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"installer with 'quote.ps1"
            source=b"Write-Output 'VERIFIED_FIXTURE_ONLY'"
            path.write_bytes(source)
            io=WindowsTimezoneIO()
            command=[io.executable,'-NoProfile','-NonInteractive','-Command',installer_bootstrap(path,hashlib.sha256(source).hexdigest())]
            result=subprocess.run(command,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(b'VERIFIED_FIXTURE_ONLY',result.stdout)
            path.write_bytes(b"Write-Output 'MUTATED_SOURCE_MUST_NOT_RUN'")
            changed=subprocess.run(command,capture_output=True,timeout=15)
            self.assertNotEqual(changed.returncode,0)
            self.assertNotIn(b'MUTATED_SOURCE_MUST_NOT_RUN',changed.stdout)

    def test_full_installer_is_parseable_without_running_and_command_is_bounded(self):
        seen=[]
        def runner(command,**kwargs):
            import base64
            bootstrap=base64.b64decode(kwargs['input']).decode('utf-16-le')
            self.assertLess(len(bootstrap),4000)
            self.assertNotIn('ExecutionPolicy',bootstrap)
            path=next(Path(tempfile.gettempdir()).glob('envscope-timezone-*/installer.ps1'))
            source=path.read_text(encoding='utf-8')
            self.assertIn('function Record',source)
            self.assertIn('transactionLock.Dispose()',source)
            parser="$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("+"'"+str(path).replace("'","''")+"'"+",[ref]$t,[ref]$e);if($e.Count){$e | Out-String;exit 1}"
            check=subprocess.run([WindowsTimezoneIO().executable,'-NoProfile','-NonInteractive','-Command',parser],capture_output=True,timeout=15)
            self.assertEqual(check.returncode,0,check.stdout+check.stderr)
            seen.append(True)
            return subprocess.CompletedProcess(command,1223,b'',b'')
        with self.assertRaises(ConsentError):WindowsTimezoneIO(runner=runner).execute({'fixture_data':'no system writes'})
        self.assertEqual(seen,[True])
