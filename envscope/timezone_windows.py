"""Reviewed, protected SYSTEM task running only the compiled timezone worker."""
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

from . import __release__
from .consent import operation_outcome, raise_for_consent
from .region_setup import current_region
from .system_network_windows import COMMON, powershell, quote
from .target_environment import fingerprint

# Reuse the existing reviewed ACL, reparse and atomic JSON-write primitives.
PROTECTION = COMMON[COMMON.index('function Assert-Protected'):COMMON.index('$Root=@ROOT@')]
HEADER = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$env:PSModulePath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/Modules'

@PROTECTION@
$Root=@ROOT@;$TaskName=@TASK@;$Fixture=@FIXTURE@
$Worker=Join-Path $Root 'timezone-helper.exe'
$Baseline=Join-Path $Root 'baseline.ini';$Receipt=Join-Path $Root 'transaction.json'
$WorkerArgs=@ARGS@
if([IO.DriveInfo]::new([IO.Path]::GetPathRoot($Root)).DriveType -ne 'Fixed'){throw 'local fixed volume required'}
function Hash($path) {if(-not(Test-Path -LiteralPath $path)){return ''};Assert-Protected $path;return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Ini($path) {
 if(-not(Test-Path -LiteralPath $path)){return @{}}
 Assert-Protected $path;if((Get-Item -LiteralPath $path).Length -gt 8192){throw 'oversized ini'}
 $value=@{};foreach($line in [IO.File]::ReadAllLines($path)){if($line -eq '[guard]' -or -not $line.Trim()){continue};$parts=$line -split '=',2;if($parts.Count -ne 2 -or $value.ContainsKey($parts[0])){throw 'invalid ini'};$value[$parts[0]]=$parts[1]};return $value
}
function Read-Task {
 $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
 try{$t=$scheduler.GetFolder('\').GetTask($TaskName)}catch{$e=$_.Exception;while($e){if($e.HResult -eq -2147024894){return $null};$e=$e.InnerException};throw}
 $d=$t.Definition;$a=$d.Actions.Item(1)
 if($t.Name -cne $TaskName -or $d.Actions.Count -ne 1 -or $a.Type -ne 0 -or $a.Path -cne $Worker -or $a.Arguments -cne $WorkerArgs -or $a.WorkingDirectory -cne $Root -or $d.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $d.Principal.RunLevel -ne 1){throw 'foreign task'}
 return @{Settings=@{Enabled=[bool]$t.Enabled};State=$(if($t.State -eq 4){'Running'}else{'Ready'})}
}
function Snapshot {
 No-Links $Root
 if(Test-Path -LiteralPath $Root){Assert-Protected ([IO.DirectoryInfo]::new($Root).Parent.FullName);Assert-Protected $Root}
 $task=Read-Task;$base=Ini $Baseline;$status=Ini (Join-Path $Root 'status.ini');$receipt=@{}
 if(Test-Path -LiteralPath $Receipt){Assert-Protected $Receipt;if((Get-Item -LiteralPath $Receipt).Length -gt 65536){throw 'oversized receipt'};$receipt=Get-Content -LiteralPath $Receipt -Raw | ConvertFrom-Json}
 if($base.Count -and ($base.format -cne '1' -or $base.worker_sha256 -cne (Hash $Worker) -or $base.owner -cnotmatch '^S-1-5(-[0-9]+)+$')){throw 'invalid baseline'}
 if($task -and -not $base.Count -and $receipt.state -notin @('pending','partial')){throw 'orphan task'}
 return @{baseline=$base;status=$status;transaction=$receipt;registered=($null -ne $task);enabled=($null -ne $task -and $task.Settings.Enabled);baseline_sha=(Hash $Baseline);worker_sha=(Hash $Worker);pending=($receipt.state -in @('pending','partial'))}
}
function New-Root($path) {
 No-Links $path;if(Test-Path -LiteralPath $path){Assert-Protected $path;return}
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')){$rights=if($sid -eq 'S-1-5-32-545'){'ReadAndExecute'}else{'FullControl'};$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,'ContainerInherit,ObjectInherit','None','Allow'))}
 [void][IO.Directory]::CreateDirectory($path,$acl);Assert-Protected $path
}
function Register-Guard([bool]$enabled) {
 $action=New-ScheduledTaskAction -Execute $Worker -Argument $WorkerArgs -WorkingDirectory $Root
 $triggers=@((New-ScheduledTaskTrigger -AtStartup),(New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 1)))
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 30) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
 # Ordinary sessions can inspect the task; only SYSTEM/administrators can run,
 # change or remove it. Do not elevate the main application to read status.
 $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
 $scheduler.GetFolder('\').GetTask($TaskName).SetSecurityDescriptor('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)',0)
 if(-not $enabled){Disable-ScheduledTask -TaskName $TaskName | Out-Null}
}
function Stop-Guard {
 $task=Read-Task;if($task){Disable-ScheduledTask -TaskName $TaskName | Out-Null;Stop-ScheduledTask -TaskName $TaskName
  for($i=0;$i -lt 20;$i++){if([string](Read-Task).State -ne 'Running'){break};Start-Sleep -Milliseconds 100}
  if([string](Read-Task).State -eq 'Running'){throw 'worker still running'}
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
 }
}
function Zone {if($Fixture){return (Ini (Join-Path $Root 'clock.ini')).timezone};return (Get-TimeZone).Id}
function Set-Zone($value) {
 if($value -cnotmatch '^[A-Za-z0-9 +_-]{1,100}$'){throw 'invalid zone'}
 if($Fixture){[IO.File]::WriteAllText((Join-Path $Root 'clock.ini'),"[guard]`ntimezone=$value`nat_epoch=live`n")}else{Set-TimeZone -Id $value}
 if((Zone) -cne $value){throw 'zone readback failed'}
}
function Record($r) {
 Save $Receipt $r $true;Save (Join-Path $Root ('receipt-'+$r.id+'.json')) $r $true
 $log=Join-Path $Root ('lifecycle-'+[DateTime]::UtcNow.ToString('yyyy-MM-dd')+'.jsonl')
 if(Test-Path -LiteralPath $log){Assert-Protected $log}
 $entry=@{at_epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();transaction=$r.id;state=$r.state;action=$r.action;fixture=$Fixture}
 $bytes=[Text.Encoding]::UTF8.GetBytes(($entry|ConvertTo-Json -Compress)+"`n")
 $stream=[IO.File]::Open($log,'Append','Write','Read');try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Protect $log $false $true
}
'''

TRANSACTION = r'''
Import-Module (Join-Path $env:PSModulePath 'ScheduledTasks/ScheduledTasks.psd1')
$planPath=@INPUT@;$expected=@SHA@
New-Root ([IO.DirectoryInfo]::new($Root).Parent.FullName);New-Root $Root
$lockPath=Join-Path $Root 'transaction.lock';if(Test-Path -LiteralPath $lockPath){Assert-Protected $lockPath}
$transactionLock=[IO.File]::Open($lockPath,'OpenOrCreate','ReadWrite','None')
$stage=Join-Path $Root ('.stage-'+[guid]::NewGuid().ToString('N'));New-Root $stage
try {
 Copy-Item -LiteralPath $planPath -Destination (Join-Path $stage 'plan.json');Protect (Join-Path $stage 'plan.json') $false $false
 if((Hash (Join-Path $stage 'plan.json')) -cne $expected){throw 'plan changed'}
 $p=Get-Content -LiteralPath (Join-Path $stage 'plan.json') -Raw | ConvertFrom-Json
 if($p.nonce -cnotmatch '^[a-f0-9]{32}$' -or $p.owner -cnotmatch '^S-1-5(-[0-9]+)+$' -or $p.action -notin @('install','remove','restore')){throw 'invalid plan'}
 $now=Snapshot
 if($now.baseline_sha -cne $p.before.baseline_sha -or $now.worker_sha -cne $p.before.worker_sha -or $now.registered -ne $p.before.registered -or $now.enabled -ne $p.before.enabled -or $now.transaction.id -cne $p.before.transaction.id){throw 'state changed'}
 if($now.baseline.Count -and $now.baseline.owner -cne $p.owner){throw 'foreign owner'}
 if($p.action -eq 'restore') {
  $r=$now.transaction;if($r.id -cne $p.restore_id -or $r.owner -cne $p.owner -or $r.state -notin @('committed','pending','partial')){throw 'foreign receipt'}
  $backup=Join-Path $Root ('backup-'+$r.id);Assert-Protected $backup
  foreach($name in @('timezone-helper.exe','baseline.ini','state.ini','status.ini')){$old=Join-Path $backup $name;if($r.hashes.$name -and (Hash $old) -cne $r.hashes.$name){throw 'backup changed'}}
  Stop-Guard
  foreach($name in @('timezone-helper.exe','baseline.ini','state.ini','status.ini')){
   $old=Join-Path $backup $name;$dest=Join-Path $Root $name
   if(Test-Path -LiteralPath $old){if((Hash $old) -cne $r.hashes.$name){throw 'backup changed'};if(Test-Path -LiteralPath $dest){Assert-Protected $dest};Copy-Item -LiteralPath $old -Destination $dest -Force;Protect $dest $false $true}
   elseif(Test-Path -LiteralPath $dest){Assert-Protected $dest;Remove-Item -LiteralPath $dest -Force}
  }
  Set-Zone $r.before_zone
  if($r.before_registered){Register-Guard ([bool]$r.before_enabled)}
  $r.state='restored';Record $r
 } else {
  if($now.pending){throw 'recovery required'}
  if((Zone) -cne $p.observed){throw 'zone changed'}
  if($p.action -eq 'install') {
   Copy-Item -LiteralPath $p.worker.path -Destination (Join-Path $stage 'worker.exe');Protect (Join-Path $stage 'worker.exe') $false $true
   if((Hash (Join-Path $stage 'worker.exe')) -cne $p.worker.sha256){throw 'worker changed'}
  }
  $backup=Join-Path $Root ('backup-'+$p.nonce);New-Root $backup;$hashes=@{}
  # Preserve a durable receipt before changing task registration. A captured
  # pending worker state stays pending on rollback instead of pretending success.
  foreach($name in @('timezone-helper.exe','baseline.ini','state.ini','status.ini')){
   $file=Join-Path $Root $name;if(Test-Path -LiteralPath $file){Assert-Protected $file;Copy-Item -LiteralPath $file -Destination (Join-Path $backup $name);Protect (Join-Path $backup $name) $false $true;$hashes[$name]=Hash (Join-Path $backup $name)}
  }
  $r=@{format=1;id=$p.nonce;owner=$p.owner;state='pending';before_zone=$p.observed;before_registered=$now.registered;before_enabled=$now.enabled;hashes=$hashes;fixture=$Fixture;action=$p.action}
  Record $r
  if($Fixture -and $p.fixture_interrupt){throw 'fixture interruption'}
  Stop-Guard
  if($p.action -eq 'install') {
   if($p.target -cnotmatch '^[A-Za-z0-9 +_-]{1,100}$' -or $p.release -cnotmatch '^v[0-9a-zA-Z.+-]+$'){throw 'invalid target'}
   Copy-Item -LiteralPath (Join-Path $stage 'worker.exe') -Destination $Worker -Force;Protect $Worker $false $true
   $original=if($now.baseline.original){$now.baseline.original}else{$p.observed}
   $ini="[guard]`nformat=1`nowner=$($p.owner)`ntarget=$($p.target)`noriginal=$original`nrelease=$($p.release)`nworker_sha256=$($p.worker.sha256)`nnonce=$($p.nonce)`n"
   [IO.File]::WriteAllText($Baseline,$ini,[Text.UTF8Encoding]::new($false));Protect $Baseline $false $true
   foreach($name in @('state.ini','status.ini')){$file=Join-Path $Root $name;if(Test-Path -LiteralPath $file){Assert-Protected $file;Remove-Item -LiteralPath $file -Force}}
   if($Fixture){& $Worker --once $Root}else{& $Worker --once};if($LASTEXITCODE -ne 0 -or (Zone) -cne $p.target){throw 'worker failed'}
   Register-Guard $true
  } else {
   if($p.restore){Set-Zone $now.baseline.original}
   if(Test-Path -LiteralPath $Baseline){Assert-Protected $Baseline;Remove-Item -LiteralPath $Baseline -Force}
  }
  $r.after_baseline_sha=Hash $Baseline;$r.after_worker_sha=Hash $Worker
  $r.state='committed';Record $r
 }
} catch {if($r -and $r.state -ne 'restored'){$r.state='partial';Record $r};throw}
finally {
 # Keep stage and receipts for recovery; never recursively delete system paths.
 $transactionLock.Dispose()
}
'''


class WindowsTimezoneIO:
    fixture = False
    def __init__(self, *, runner=subprocess.run, worker=None, root=None, task=None, fixture=False):
        self.runner=runner;self._worker=worker;self.fixture=fixture;self.root=root;self.task=task or 'EnvScope-TimezoneGuard';self.clock=time.time
        if (root is not None or task is not None) and not fixture:
            raise ValueError('Production task and path are fixed')
        if fixture and (not root or not re.fullmatch(r'EnvScope-TimezoneFixture-[a-f0-9]{8,32}',self.task)):
            raise ValueError('Isolated fixture identity required')
        self.executable=powershell()

    def worker(self):
        if self._worker:return self._worker()
        from .timezone_service import bundle_worker
        return bundle_worker(system='Windows')

    def script(self, tail):
        root=quote(Path(self.root).resolve()) if self.fixture else "(Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EnvScope/TimezoneGuard')"
        args=quote('--once "'+str(Path(self.root).resolve())+'"') if self.fixture else "'--once'"
        header=HEADER.replace('@PROTECTION@',PROTECTION)
        return header.replace('@ROOT@',root).replace('@TASK@',quote(self.task)).replace('@FIXTURE@','$true' if self.fixture else '$false').replace('@ARGS@',args)+tail

    def _read(self, tail):
        encoded=base64.b64encode(self.script(tail).encode('utf-16-le')).decode()
        value=self.runner([self.executable,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,timeout=15,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if value.returncode or len(value.stdout or b'')>131072:
            raise ValueError('无法核实系统时区任务权限、归属或记录。')
        return json.loads(value.stdout)

    def inspect(self):
        value=self._read('$value=Snapshot;$value.current_owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$value | ConvertTo-Json -Depth 12 -Compress')
        self._owner=value.pop('current_owner');return value
    def owner(self):
        if not hasattr(self,'_owner'):self.inspect()
        return self._owner
    def authority(self):
        value=self.inspect();beat=value.get('status',{})
        return {**value,'registered':value['registered'] and value['enabled'],'foreign_owner':bool(value['baseline']) and value['baseline'].get('owner')!=self.owner(),
                'status':{**beat,'at_epoch':float(beat.get('at_epoch',0)),'initial':beat.get('initial')!='0'}}

    def execute(self,payload):
        data=json.dumps(payload,sort_keys=True).encode()
        with tempfile.TemporaryDirectory(prefix='envscope-timezone-') as folder:
            path=Path(folder).resolve()/'plan.json';path.write_bytes(data)
            code=self.script(TRANSACTION.replace('@INPUT@',quote(path)).replace('@SHA@',quote(hashlib.sha256(data).hexdigest())))
            # Keep the reviewed source readable. The bounded elevated entry point
            # hashes one in-memory snapshot, then runs precisely those bytes.
            # No mutable script path is retained by the SYSTEM task.
            source=Path(folder).resolve()/'installer.ps1';source.write_bytes(code.encode('utf-8'))
            bootstrap=installer_bootstrap(source,hashlib.sha256(source.read_bytes()).hexdigest())
            encoded=base64.b64encode(bootstrap.encode('utf-16-le')).decode()
            command=[self.executable,'-NoProfile','-NonInteractive','-EncodedCommand',encoded]
            if len(subprocess.list2cmdline(command).encode('utf-16-le'))//2>32600:raise ValueError('时区操作超出命令长度限制，未执行。')
            launcher=("$ErrorActionPreference='Stop';$code=[Console]::In.ReadToEnd();if($code -cnotmatch '^[A-Za-z0-9+/=]+$' -or $code.Length -gt 32500){exit 65};"
                "$o=@{FilePath="+quote(self.executable)+";ArgumentList=@('-NoProfile','-NonInteractive','-EncodedCommand',$code);WindowStyle='Hidden';Wait=$true;PassThru=$true};"
                "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){$o.Verb='RunAs'};"
                "try{$v=Start-Process @o;exit $v.ExitCode}catch{$e=$_.Exception;while($e){if($e -is [ComponentModel.Win32Exception]){exit $e.NativeErrorCode};$e=$e.InnerException};exit 1}")
            result=self.runner([self.executable,'-NoProfile','-NonInteractive','-Command',launcher],input=encoded.encode(),capture_output=True,timeout=150,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            raise_for_consent(result,'Windows')


def installer_bootstrap(source, expected):
    """Bind a foreground consent request to readable, byte-exact source.

    Loading the snapshot once avoids a verify/execute path race. OS application
    control and PowerShell language restrictions still apply; no policy changes
    or execution-policy switches are made here.
    """
    if not re.fullmatch(r'[a-f0-9]{64}',expected):raise ValueError('Invalid source digest')
    return ("$ErrorActionPreference='Stop';$path="+quote(source)+";"
            "if((Get-Item -LiteralPath $path).Length -gt 196608){throw 'oversized installer'};"
            "$bytes=[IO.File]::ReadAllBytes($path);$hash=[Security.Cryptography.SHA256]::Create();"
            "try{$actual=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};"
            "if($actual -cne '"+expected+"'){throw 'reviewed installer changed'};"
            "$source=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);"
            "& ([scriptblock]::Create($source))")


def stable(value):
    return {key:value.get(key) for key in ('baseline_sha','worker_sha','registered','enabled')} | {'transaction':{'id':value.get('transaction',{}).get('id')}}


class WindowsTimezoneService:
    system='Windows'
    def __init__(self,store,reader,*,io=None,**kwargs):
        self.store,self.reader=store,reader;self.io=io or WindowsTimezoneIO();self.plans={}

    def status(self):
        try:
            snapshot=self.io.inspect();base=snapshot['baseline'];beat=snapshot['status'];receipt=snapshot.get('transaction',{})
            owner=base.get('owner')==self.io.owner() if base else receipt.get('owner')==self.io.owner()
            stamp=float(beat.get('at_epoch',0));current=(beat.get('format')=='1' and beat.get('guard_policy')=='2' and beat.get('target')==base.get('target') and beat.get('release')==base.get('release') and beat.get('fixture')==str(int(self.io.fixture)) and beat.get('initial')=='0' and 0<=self.io.clock()-stamp<180)
            state=('recovery_required' if snapshot['pending'] else 'conflict' if base and not owner else 'not_installed' if not base else
                   'unregistered' if not snapshot['registered'] or not snapshot['enabled'] else 'waiting' if not current else
                   'active' if beat.get('state') in ('healthy','restored') and beat.get('observed')==base.get('target') else 'attention')
            reasons={'recovery_required':'上次系统时区操作未完成，请先预览恢复。','conflict':'时区任务属于另一用户，未覆盖其基线。',
                     'not_installed':'尚未授权独立的系统时区任务。','unregistered':'时区任务未注册或被停用，请重新预览。',
                     'waiting':'等待当前基线的有效心跳，尚未计为自动守护正常。','active':'系统时区基线已读回，每 60 秒检查；后台不弹授权窗口。',
                     'attention':'系统时区保持需要处理，请查看记录后重新审核。'}
            return {'supported':True,'state':state,'reason':reasons[state],'installed':bool(base),'registered':snapshot['registered'] and snapshot['enabled'],
                    'owner':owner,'target':base.get('target'),'original':base.get('original'),'observed':beat.get('observed'),'heartbeat_at':stamp,
                    'pending':snapshot['pending'],'needs_update':bool(base) and base.get('release')!=__release__,
                    'can_undo':owner and receipt.get('state')=='committed','release':base.get('release'),
                    'intentionally_removed':not base and owner and (receipt.get('state')=='restored' or receipt.get('state')=='committed' and receipt.get('action')=='remove'),
                    'journal_path':'%ProgramData%/EnvScope/TimezoneGuard','capability':'protected-native-task'}
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
            return {'supported':True,'state':'attention','reason':'系统时区任务权限或归属未能核实，未报告守护正常。'}

    def prepare(self,report,*,remove=False,restore=False):
        if type(remove) is not bool or type(restore) is not bool:raise ValueError('时区选项无效')
        from .remedies import SolutionPlans
        from .regions import region_finding,PARTIAL
        from .model import Status
        settings=self.store.settings()
        if not remove and (not SolutionPlans._current(report) or not settings.get('environment_confirmed') or report.get('environment',{}).get('fingerprint')!=fingerprint(settings)):
            return {'state':'retest_required','reason':'先按当前目标完成新的检测，再授权时区保持。'}
        if not remove and (not settings.get('usage_country') or settings['usage_country'] in PARTIAL or region_finding([],settings).status==Status.FAIL or not any(f['id']=='target.region' and f['status']=='pass' for f in report.get('findings',[]))):
            return {'state':'blocked','reason':'官方地区条件未核实通过，未生成环境修改。'}
        snapshot=self.io.inspect();base=snapshot['baseline'];owner=self.io.owner()
        if snapshot['pending']:return {'state':'recovery_required','reason':'请先恢复上次未完成的时区事务。'}
        if base and base.get('owner')!=owner:return {'state':'blocked','reason':'时区基线属于另一用户。'}
        if remove and not base:return {'state':'guided','reason':'没有已安装的系统时区保持任务。'}
        observed=current_region(self.reader())['timezone'];target=base.get('target') if remove else settings.get('timezone')
        from .region_profiles import profiles
        if target not in {p['timezone'] for p in profiles('Windows')} or not re.fullmatch('[A-Za-z0-9 +_-]{1,100}',observed):
            return {'state':'guided','reason':'请先选择可核对的城市与系统时区。'}
        worker=self.io.worker() if not remove else None
        payload={'nonce':secrets.token_hex(16),'owner':owner,'action':'remove' if remove else 'install','before':stable(snapshot),
                 'observed':observed,'target':target,'restore':restore,'worker':worker,'release':__release__}
        return self._plan(payload, ['申请一次 Windows 系统授权；仅运行受保护的原生时区任务，影响整台电脑。',
            ('停用时区任务；'+('恢复安装前时区 '+base['original'] if restore else '保留当前时区。')) if remove else
            '保持 '+target+'；每 60 秒检查，每次修复前留痕，至少间隔 5 分钟、24 小时最多恢复 3 次。',
            '失败或中断时暂停自动写入并保留日志、备份；主应用和账号操作继续以普通用户运行。'])

    def _plan(self,payload,effects):
        token=secrets.token_urlsafe(20);signature=hashlib.sha256(json.dumps(payload['before'],sort_keys=True).encode()).hexdigest()
        self.plans={token:{'payload':payload,'deadline':time.monotonic()+90,'fingerprint':fingerprint(self.store.settings())}}
        return {'state':'planned','plan_id':token,'effects':effects,'transaction_nonce':payload.get('restore_id',payload['nonce']),
                'before_signature':signature,'reason':'核对后确认；Windows 仅在实际系统操作时申请授权。'}

    def apply(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if not plan or time.monotonic()>plan['deadline'] or plan['fingerprint']!=fingerprint(self.store.settings()):return {'state':'retest_required','reason':'方案已过期或目标改变，请重新预览。'}
        payload=plan['payload'];snapshot=self.io.inspect()
        if stable(snapshot)!=payload['before'] or (payload['action']=='install' and self.io.worker()!=payload['worker']):return {'state':'retest_required','reason':'服务或辅助程序已改变，请重新预览。'}
        del self.plans[token]
        try:self.io.execute(payload)
        except (OSError,ValueError,subprocess.SubprocessError) as exc:
            return {'state':'partial','reason':str(exc)[:240],'status':self.status(),**operation_outcome(exc),'transaction_nonce':payload.get('restore_id',payload['nonce'])}
        after=self.io.inspect();r=after.get('transaction',{});nonce=payload.get('restore_id',payload['nonce'])
        good=r.get('id')==nonce and r.get('state')==('restored' if payload['action']=='restore' else 'committed') and not after['pending']
        if payload['action']=='install':good=good and after['registered'] and after['enabled'] and after['baseline'].get('target')==payload['target'] and current_region(self.reader())['timezone']==payload['target']
        elif payload['action']=='remove':good=good and not after['registered'] and not after['baseline']
        return {'state':'completed' if good else 'partial','status':self.status(),'needs_retest':True,'transaction_nonce':nonce,
                'reason':'系统时区操作已读回，请复检并确认后台心跳。' if good else '实际状态未完整读回，请保留记录并恢复。'}

    def _restore_plan(self,*,pending=False,nonce=None):
        snapshot=self.io.inspect();record=snapshot.get('transaction',{});owner=self.io.owner()
        if record.get('owner')!=owner:return {'state':'blocked','reason':'恢复记录不属于当前用户。'}
        if nonce and record.get('id')!=nonce:return {'state':'retest_required','reason':'已有后续时区操作，未覆盖。'}
        if (pending and not snapshot['pending']) or record.get('state') not in ('committed','partial','pending'):return {'state':'guided','reason':'没有符合条件的恢复记录。'}
        if record.get('state')=='committed' and (record.get('after_baseline_sha')!=snapshot['baseline_sha'] or record.get('after_worker_sha')!=snapshot['worker_sha']):
            return {'state':'blocked','reason':'事务完成后的系统基线或程序又有变化，未覆盖后续修改。'}
        payload={'nonce':secrets.token_hex(16),'owner':owner,'action':'restore','before':stable(snapshot),'restore_id':record['id']}
        return self._plan(payload,['申请系统授权，停止当前时区任务，并恢复最新事务保存的时区、辅助程序与后台任务状态。','保留完整备份和日志；恢复后重新检测。'])

    def prepare_recovery(self):return self._restore_plan(pending=True)
    def prepare_undo(self,nonce=None):return self._restore_plan(nonce=nonce)
    def recover(self,token,confirmed=False):return self.apply(token,confirmed)
    def undo(self,token,confirmed=False):return self.apply(token,confirmed)
    def rollback_latest(self,nonce,confirmed=False,*,unchanged_signature=None):
        if confirmed is not True:return {'state':'confirmation_required'}
        snapshot=self.io.inspect()
        if snapshot.get('transaction',{}).get('id')!=nonce and unchanged_signature==hashlib.sha256(json.dumps(stable(snapshot),sort_keys=True).encode()).hexdigest():return {'state':'completed','reason':'时区任务尚未变化。'}
        plan=self._restore_plan(nonce=nonce)
        return self.apply(plan['plan_id'],True) if plan.get('state')=='planned' else plan
