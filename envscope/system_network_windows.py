"""Windows network operations use one reviewed encoded command, never a .ps1 path.

The unelevated launcher passes the immutable encoded command over stdin. Data is
copied and hashed after elevation; system modules are loaded from Windows only.
"""
import base64
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from . import __release__
from .system_network import validate_snapshot


BACKEND=r'''
Import-Module (Join-Path $env:PSModulePath 'NetAdapter/NetAdapter.psd1') -ErrorAction Stop
function Read-Network {
 $rows=@()
 foreach($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)) {
  $escaped=[System.Management.Automation.WildcardPattern]::Escape($adapter.Name)
  $bindings=@(Get-NetAdapterBinding -Name $escaped -AllBindings -IncludeHidden -ErrorAction Stop | Where-Object {$_.Name -ceq $adapter.Name})
  $v6=@($bindings | Where-Object {$_.ComponentID -ceq 'ms_tcpip6'})
  if($v6.Count -eq 0){continue}; if($v6.Count -ne 1){throw 'binding ambiguity'}
  $other=@{};foreach($binding in $bindings){if($binding.ComponentID -cne 'ms_tcpip6'){$other[[string]$binding.ComponentID]=[bool]$binding.Enabled}}
  $rows+=@{id=([guid]$adapter.InterfaceGuid).ToString('D').ToLowerInvariant();name=[string]$adapter.Name;active=([string]$adapter.Status -eq 'Up');ipv6_enabled=[bool]$v6[0].Enabled;config=$other}
 }
 return @{format=1;owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;adapters=@($rows)}
}
function Write-V6($id,[bool]$enabled) {
 $adapter=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {([guid]$_.InterfaceGuid).ToString('D').ToLowerInvariant() -ceq $id})
 if($adapter.Count -ne 1){throw 'adapter changed'}
 $escaped=[System.Management.Automation.WildcardPattern]::Escape($adapter[0].Name)
 $binding=@(Get-NetAdapterBinding -Name $escaped -ComponentID ms_tcpip6 -IncludeHidden -ErrorAction Stop | Where-Object {$_.Name -ceq $adapter[0].Name})
 if($binding.Count -ne 1){throw 'binding changed'}
 $binding[0] | Set-NetAdapterBinding -Enabled $enabled -Confirm:$false -ErrorAction Stop
}
function Flush-Dns {
 Import-Module (Join-Path $env:PSModulePath 'DnsClient/DnsClient.psd1') -ErrorAction Stop
 Clear-DnsClientCache -ErrorAction Stop
}
'''

COMMON=r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$env:PSModulePath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/Modules'
$Fixture=@FIXTURE@
@BACKEND@
function Shape($data) {
 if($data.format -ne 1 -or @($data.adapters).Count -gt 256){throw 'invalid snapshot'}
 $seen=@{}
 foreach($r in @($data.adapters)) {
  if($r.id -cnotmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or $seen.ContainsKey($r.id) -or $r.ipv6_enabled -isnot [bool] -or $null -eq $r.config){throw 'invalid adapter'}
  $seen[$r.id]=$true
 }
}
function Config-Key($config) {
 if($config -is [Collections.IDictionary]){$keys=@($config.Keys)}else{$keys=@($config.psobject.Properties.Name)}
 $values=foreach($key in @($keys | Sort-Object -CaseSensitive)) {
  $value=$config.$key;if($value -isnot [bool]){throw 'unknown binding value'}
  [string]$key.Length+':'+$key+'='+[int][bool]$value
 }
 return ($values -join "`n")
}
function Matches($current,$before,[bool]$disabled) {
 Shape $current
 foreach($r in @($before)) {
  $found=@($current.adapters | Where-Object {$_.id -ceq $r.id})
  if($found.Count -ne 1 -or (Config-Key $found[0].config) -cne (Config-Key $r.config)){return $false}
  $wanted=$r.ipv6_enabled;if($disabled){$wanted=$false}
  if($found[0].ipv6_enabled -ne $wanted){return $false}
 }
 return $true
}
function Assert-Protected($path) {
 if(-not(Test-Path -LiteralPath $path)){throw 'missing protected path'}
 $entry=Get-Item -LiteralPath $path -Force
 if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse point'}
 $acl=Get-Acl -LiteralPath $path
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'wrong owner'}
 $write=[Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ($rule.FileSystemRights -band $write)){throw 'writable protected path'}
 }
}
function No-Links($path) {
 for($p=[IO.DirectoryInfo]::new($path);$null -ne $p;$p=$p.Parent){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'redirected root path'}}
}
function Protect($path,[bool]$directory,[bool]$public) {
 if($directory){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}
 else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]::None}
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl',$inherit,'None','Allow'))
 }
 if($public){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute',$inherit,'None','Allow'))}
 Set-Acl -LiteralPath $path -AclObject $acl
 Assert-Protected $path
}
function Save($path,$value,[bool]$public) {
 $temporary=Join-Path $Root ('.write-'+[guid]::NewGuid().ToString('N'))
 try {
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value | ConvertTo-Json -Depth 30 -Compress))
  $file=[IO.File]::Open($temporary,'CreateNew','Write','None')
  try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
  Protect $temporary $false $public
  if(Test-Path -LiteralPath $path){Assert-Protected $path;[IO.File]::Replace($temporary,$path,$null)}else{[IO.File]::Move($temporary,$path)}
  Assert-Protected $path
 }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
$Root=@ROOT@
$Latest=Join-Path $Root 'latest.json'
function Read-Record {
 if(-not(Test-Path -LiteralPath $Latest)){return @{state='not_configured';id=''}}
 Assert-Protected $Root;Assert-Protected $Latest
 $record=[IO.File]::ReadAllText($Latest,[Text.Encoding]::UTF8) | ConvertFrom-Json
 if($record.id -cnotmatch '^[0-9a-f]{32}$' -or $record.format -ne 1 -or $record.fixture -ne $Fixture -or $record.state -notin @('prepared','partial','committed','rolled_back','restored')){throw 'invalid receipt'}
 Shape @{format=1;adapters=@($record.adapters)}
 return $record
}
function Publish($record,$state) {
 $record.state=$state;$record.at_epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
 Save (Join-Path $Root ('record-'+$record.id+'.private.json')) $record $false
 Save $Latest $record $true
 $line=@{at_epoch=$record.at_epoch;transaction=$record.id;phase=$state;fixture=$Fixture} | ConvertTo-Json -Compress
 $log=Join-Path $Root ('events-'+[DateTime]::UtcNow.ToString('yyyy-MM-dd')+'.private.jsonl')
 if(Test-Path -LiteralPath $log){Assert-Protected $log}
 $stream=[IO.File]::Open($log,'Append','Write','Read');try{$bytes=[Text.Encoding]::UTF8.GetBytes($line+"`n");$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Restore-Original($before) {
 $current=Read-Network
 foreach($r in @($before)) {
  $live=@($current.adapters | Where-Object {$_.id -ceq $r.id})
  if($live.Count -ne 1 -or (Config-Key $live[0].config) -cne (Config-Key $r.config)){throw 'later network change'}
 }
 foreach($r in @($before)) {
  $live=@($current.adapters | Where-Object {$_.id -ceq $r.id})[0]
  if($live.ipv6_enabled -ne $r.ipv6_enabled){Write-V6 $r.id $r.ipv6_enabled}
 }
 if(-not(Matches (Read-Network) $before $false)){throw 'restore readback failed'}
}
'''

TRANSACTION=r'''
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator required'}
$parent=Split-Path -Parent $Root
No-Links $Root
foreach($directory in @($parent,$Root)) {
 if(-not(Test-Path -LiteralPath $directory)){[IO.Directory]::CreateDirectory($directory) | Out-Null;Protect $directory $true $true}
 Assert-Protected $directory
}
$leasePath=Join-Path $Root '.transaction.lock'
if(Test-Path -LiteralPath $leasePath){Assert-Protected $leasePath}
if(-not(Test-Path -LiteralPath $leasePath)){[IO.File]::WriteAllBytes($leasePath,[byte[]]@());Protect $leasePath $false $false}
$lease=[IO.File]::Open($leasePath,'Open','ReadWrite','None')
$inputPath=Join-Path $Root ('.input-'+[guid]::NewGuid().ToString('N'))
try {
 [IO.File]::Copy(@DATA_FILE@,$inputPath,$false);Protect $inputPath $false $false
 if((Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '@DATA_SHA@'){throw 'reviewed data changed'}
 if((Get-Item -LiteralPath $inputPath).Length -gt 2097152){throw 'oversized data'}
 $plan=[IO.File]::ReadAllText($inputPath,[Text.Encoding]::UTF8) | ConvertFrom-Json
 if($plan.format -ne 1 -or $plan.owner -cnotmatch '^S-1-([0-9]+-)*[0-9]+$'){throw 'invalid actor'}
 $previous=Read-Record
 if('@ACTION@' -eq 'restore') {
  if($plan.record_id -cne $previous.id -or $plan.owner -cne $previous.owner){throw 'receipt changed'}
  $backup=Join-Path $Root ('record-'+$previous.id+'.private.json');Assert-Protected $backup
  $original=[IO.File]::ReadAllText($backup,[Text.Encoding]::UTF8) | ConvertFrom-Json
  if($original.owner -cne $previous.owner -or $original.id -cne $previous.id){throw 'backup mismatch'}
  Restore-Original @($original.adapters);Publish $original 'restored'
 }else {
  Shape $plan
  if($plan.nonce -cnotmatch '^[a-f0-9]{32}$' -or $plan.expected_record -cne $previous.id -or $previous.state -in @('prepared','partial') -or $plan.flush_dns -isnot [bool]){throw 'stale plan'}
  if(Test-Path -LiteralPath (Join-Path $Root ('record-'+$plan.nonce+'.private.json'))){throw 'nonce already used'}
  if(-not(Matches (Read-Network) @($plan.adapters) $false)){throw 'network changed'}
  $record=@{format=1;id=$plan.nonce;owner=$plan.owner;adapters=@($plan.adapters);fixture=$Fixture;release='@RELEASE@';state='prepared';at_epoch=0;dns_flush='not_requested'}
  if($plan.flush_dns){$record.dns_flush='pending'}
  Publish $record 'prepared'
  try {
   foreach($r in @($plan.adapters)){Write-V6 $r.id $false}
   if(-not(Matches (Read-Network) @($plan.adapters) $true)){throw 'write readback failed'}
  }catch {
   try{Restore-Original @($plan.adapters);Publish $record 'rolled_back'}catch{Publish $record 'partial'}
   throw 'network write not completed'
  }
  if($plan.flush_dns){try{Flush-Dns;$record.dns_flush='completed'}catch{$record.dns_flush='unverified';Publish $record 'partial';throw 'DNS flush not confirmed'}}
  Publish $record 'committed'
 }
}catch{
 try {
  $code=[string]$_.FullyQualifiedErrorId
  if($code.Length -gt 160){$code='system_operation_failed'}
  $code+=' [line '+[int]$_.InvocationInfo.ScriptLineNumber+']'
  Save (Join-Path $Root 'failure.json') @{format=1;data_sha='@DATA_SHA@';code=$code} $true
 }catch{}
 throw
}finally{
 if(Test-Path -LiteralPath $inputPath){Remove-Item -LiteralPath $inputPath -Force}
 $lease.Dispose()
}
'''


def quote(value):return "'"+str(value).replace("'","''")+"'"


def script(mode,*,data_file=None,data_sha=None,fixture_backend=None,fixture_root=None):
    if mode not in ('snapshot','status','failure','apply','restore'):raise ValueError('不支持的系统网络操作')
    if (fixture_backend is None)!=(fixture_root is None):raise ValueError('Incomplete fixture')
    root=quote(str(fixture_root)) if fixture_root else "(Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EnvScope/network')"
    value=COMMON.replace('@FIXTURE@','$true' if fixture_backend is not None else '$false').replace('@ROOT@',root)
    value=value.replace('@BACKEND@',BACKEND if fixture_backend is None else fixture_backend)
    if mode=='snapshot':return value+"\nRead-Network | ConvertTo-Json -Depth 30 -Compress\n"
    if mode=='status':return value+"\nRead-Record | ConvertTo-Json -Depth 30 -Compress\n"
    if mode=='failure':return value+"\n$p=Join-Path $Root 'failure.json';Assert-Protected $p;[IO.File]::ReadAllText($p,[Text.Encoding]::UTF8)\n"
    if not isinstance(data_sha,str) or len(data_sha)!=64 or any(c not in '0123456789abcdef' for c in data_sha):raise ValueError('网络修改摘要无效')
    return value+TRANSACTION.replace('@ACTION@',mode).replace('@DATA_FILE@',quote(data_file)).replace('@DATA_SHA@',data_sha).replace('@RELEASE@',__release__)


def powershell():
    buffer=ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,len(buffer)):raise OSError('Windows directory unavailable')
    return str(Path(buffer.value)/'System32/WindowsPowerShell/v1.0/powershell.exe')


class WindowsNetworkIO:
    def __init__(self,*,runner=None,executable=None):
        self.runner=runner or subprocess.run;self.executable=executable or powershell()
        self.fixture=False

    def _body(self,mode,**kwargs):return script(mode,**kwargs)

    def _read(self,mode):
        result=self.runner([self.executable,'-NoProfile','-NonInteractive','-Command',self._body(mode)],capture_output=True,
                           timeout=25,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode or len(result.stdout)>2*1024**2:raise ValueError('系统网络或恢复记录无法读取，请核对系统权限。')
        try:return json.loads(result.stdout.decode('utf-8-sig'))
        except (UnicodeError,ValueError):raise ValueError('系统网络读取结果无效。') from None

    def snapshot(self):return validate_snapshot(self._read('snapshot'))
    def status(self):
        value=self._read('status')
        if value=={'state':'not_configured','id':''}:return value
        if (not isinstance(value,dict) or type(value.get('format')) is not int or value['format']!=1
                or not isinstance(value.get('id'),str) or not re.fullmatch('[a-f0-9]{32}',value['id'])
                or value.get('fixture') is not self.fixture
                or value.get('state') not in ('prepared','partial','committed','rolled_back','restored')):
            raise ValueError('系统网络恢复记录格式无效，保留现场，请由管理员核对。')
        validate_snapshot({'format':1,'owner':value.get('owner'),'adapters':value.get('adapters')})
        return value

    def execute(self,action,payload):
        data=json.dumps(payload,ensure_ascii=True).encode()
        with tempfile.TemporaryDirectory(prefix='envscope-network-plan-') as folder:
            path=Path(folder).resolve()/'plan.private.bin';path.write_bytes(data)
            body=self._body(action,data_file=path,data_sha=hashlib.sha256(data).hexdigest())
            encoded=base64.b64encode(body.encode('utf-16-le')).decode()
            if len(encoded)>30000:raise ValueError('网络修改命令超出系统限制，未尝试执行。')
            launcher=("$ErrorActionPreference='Stop';$code=[Console]::In.ReadToEnd();"
                      "if($code.Length -gt 30000 -or $code -cnotmatch '^[A-Za-z0-9+/=]+$'){exit 65};"
                      "$options=@{FilePath="+quote(self.executable)+";ArgumentList=@('-NoProfile','-NonInteractive','-EncodedCommand',$code);WindowStyle='Hidden';Wait=$true;PassThru=$true};"
                      "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());"
                      "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){$options.Verb='RunAs'};"
                      "$process=Start-Process @options;exit $process.ExitCode")
            result=self.runner([self.executable,'-NoProfile','-NonInteractive','-Command',launcher],input=encoded.encode(),
                               capture_output=True,timeout=150,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if result.returncode:
                detail=''
                try:
                    failure=self._read('failure');code=failure.get('code','')
                    if failure.get('data_sha')==hashlib.sha256(data).hexdigest() and isinstance(code,str) and len(code)<=160:
                        detail=' 记录代码：'+code
                except (OSError,ValueError):pass
                raise ValueError('系统授权取消或网络修改未确认完成，请刷新恢复记录；没有按命令返回判定修复成功。'+detail)
