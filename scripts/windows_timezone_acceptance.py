"""CI-only SYSTEM scheduler/ACL acceptance with a compiled file-clock fixture."""
import configparser
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile
import time

from envscope.state import StateStore
from envscope.timezone_windows import WindowsTimezoneIO, WindowsTimezoneService
from scripts.build_windows_timezone import build
from scripts.environment_fixtures import report, target


def main():
    if platform.system()!='Windows' or os.environ.get('ENVSCOPE_TIMEZONE_ACCEPTANCE')!='1' or os.environ.get('CI')!='true':
        print('SKIP: opt-in Windows CI fixture only');return
    if not ctypes.windll.shell32.IsUserAnAdmin():raise RuntimeError('CI fixture requires an administrator runner, never prompts for real authorization')
    folder=ctypes.create_unicode_buffer(260)
    if ctypes.windll.shell32.SHGetFolderPathW(None,35,None,0,folder)!=0:raise RuntimeError('CommonApplicationData unavailable')
    parent=Path(folder.value).resolve()/'EnvScope';nonce=secrets.token_hex(8)
    root=(parent/('TimezoneFixture-'+nonce)).resolve();task='EnvScope-TimezoneFixture-'+nonce
    if root.parent!=parent.resolve() or not root.name.startswith('TimezoneFixture-'):raise RuntimeError('Fixture containment failed')
    tzutil=str(Path(os.environ['SystemRoot'])/'System32/tzutil.exe');before_zone=subprocess.check_output([tzutil,'/g'])
    summary={}
    with tempfile.TemporaryDirectory(prefix='envscope-windows-timezone-test-') as temporary:
        build_root=build(Path(temporary)/'build',fixture=True);binary=build_root/'timezone-helper.exe'
        worker=json.loads((build_root/'timezone-helper.json').read_text())|{'path':str(binary)}
        class FixtureIO(WindowsTimezoneIO):
            interrupt=False
            def execute(self,payload):super().execute({**payload,**({'fixture_interrupt':True} if self.interrupt else {})})
        io=FixtureIO(root=root,task=task,fixture=True,worker=lambda:worker)
        def powershell(source):
            value=subprocess.run([io.executable,'-NoProfile','-NonInteractive','-Command','[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))'],input=source.encode(),capture_output=True,timeout=30)
            if value.returncode:raise RuntimeError('Owned fixture operation failed: '+value.stderr.decode('utf-8',errors='replace')[-1500:])
            return value.stdout
        def reader():
            parser=configparser.ConfigParser();parser.read(root/'clock.ini');return {'network':{'timezone_id':parser['guard']['timezone']}}
        store=StateStore(Path(temporary)/'state');settings=target('Windows',usage_country='US',country='US',timezone='Eastern Standard Time',locale='en-US')
        store.save_settings({k:v for k,v in settings.items() if k!='environment_confirmed'},confirm_environment=True)
        service=WindowsTimezoneService(store,reader,io=io)
        try:
            powershell(io.script("New-Root ([IO.DirectoryInfo]::new($Root).Parent.FullName);New-Root $Root;Set-Zone 'China Standard Time'"))
            r=report(Path(temporary),store.settings(),'Windows')
            plan=service.prepare(r);assert plan['state']=='planned',plan
            outcome=service.apply(plan['plan_id'],True);assert outcome['state']=='completed',outcome
            first=service.status()['heartbeat_at'];cycles=[];deadline=time.monotonic()+165
            while len(cycles)<2 and time.monotonic()<deadline:
                status=service.status();stamp=status.get('heartbeat_at',0)
                if status['state']=='active' and stamp>first and (not cycles or stamp>cycles[-1]+1):
                    cycles.append(stamp);print('Observed SYSTEM fixture cycle '+str(len(cycles)),flush=True)
                time.sleep(2)
            assert len(cycles)==2,service.status()
            summary['system_scheduled_cycles']=2
            # The ACL change is confined to the disposable fixture baseline.
            powershell(io.script("$acl=Get-Acl -LiteralPath $Baseline;$script:original=$acl.Sddl;[IO.File]::WriteAllText((Join-Path $Root 'saved-acl.txt'),$acl.Sddl);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Write','Allow'));Set-Acl -LiteralPath $Baseline -AclObject $acl"))
            assert service.status()['state']=='attention'
            powershell(io.script("$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm([IO.File]::ReadAllText((Join-Path $Root 'saved-acl.txt')));Set-Acl -LiteralPath $Baseline -AclObject $acl"))
            summary['writable_acl_rejected']=True
            plan=service.prepare(r,remove=True,restore=True);assert service.apply(plan['plan_id'],True)['state']=='completed'
            assert reader()['network']['timezone_id']=='China Standard Time'
            plan=service.prepare_undo();assert service.undo(plan['plan_id'],True)['state']=='completed'
            assert reader()['network']['timezone_id']=='Eastern Standard Time'
            summary['remove_restore_undo']=True
            r=report(Path(temporary),store.settings(),'Windows');plan=service.prepare(r);io.interrupt=True
            assert service.apply(plan['plan_id'],True)['state']=='partial';assert service.status()['state']=='recovery_required'
            io.interrupt=False;plan=service.prepare_recovery();assert service.recover(plan['plan_id'],True)['state']=='completed'
            summary['interrupted_transaction_recovery']=True
            assert subprocess.check_output([tzutil,'/g'])==before_zone
            summary.update(real_timezone_unchanged=True,real_uac_consent=False,fixture_worker=True)
        finally:
            # Exact resolved fixture root was checked above; only our unique task
            # and this owned directory are removed, using PowerShell end-to-end.
            powershell(io.script("Import-Module (Join-Path $env:PSModulePath 'ScheduledTasks/ScheduledTasks.psd1');$t=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue;if($t){if($t.Actions[0].Execute -cne $Worker){throw 'foreign cleanup task'};Stop-ScheduledTask -TaskName $TaskName;Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false};No-Links $Root;if([IO.Path]::GetFullPath($Root) -cne $Root -or [IO.Path]::GetFileName($Root) -cnotmatch '^TimezoneFixture-[a-f0-9]{16}$'){throw 'unsafe cleanup root'};Remove-Item -LiteralPath $Root -Recurse -Force"))
    out=Path('artifacts/windows-timezone-acceptance.json');out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(summary,indent=2))
    print(json.dumps(summary))


if __name__=='__main__':main()
