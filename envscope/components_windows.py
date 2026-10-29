"""Fixed Windows task retirement, protected backup and compare-before-restore.

The administrator receives immutable encoded code, never an executable .ps1
from a writable folder. User input cannot supply a task name or command.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from . import __release__
from .component_inventory import Layout, WINDOWS_READ, windows_snapshot
from .system_network_windows import powershell, quote


PROTECT = r'''
function NoLinks($path) {
 for($p=[IO.DirectoryInfo]::new($path);$null -ne $p;$p=$p.Parent){if($p.Exists -and ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'redirected path'}}
}
function Safe($path) {
 $f=Get-Item -LiteralPath $path -Force
 if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'redirected receipt'}
 $a=Get-Acl -LiteralPath $path
 if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'receipt owner'}
 foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership')){throw 'writable receipt'}
 }
}
function Protect($path,[bool]$directory,[bool]$public) {
 if($directory){$a=[Security.AccessControl.DirectorySecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{$a=[Security.AccessControl.FileSecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]::None}
 $a.SetAccessRuleProtection($true,$false);$a.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($s in @('S-1-5-18','S-1-5-32-544')){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($s),'FullControl',$inherit,'None','Allow'))}
 if($public){$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Actor),'ReadAndExecute',$inherit,'None','Allow'))}
 Set-Acl -LiteralPath $path -AclObject $a;Safe $path
}
function Save($path,$v,[bool]$public) {
 $tmp=Join-Path $Root ('.next-'+[guid]::NewGuid().ToString('N'))
 try{
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($v|ConvertTo-Json -Depth 20 -Compress))
  $f=[IO.File]::Open($tmp,'CreateNew','Write','None');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
  Protect $tmp $false $public
  if(Test-Path -LiteralPath $path){Safe $path;[IO.File]::Replace($tmp,$path,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$path)}
 }finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}}
}
function Hash([string]$text) {
 $sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function ReadLast {
 if(-not(Test-Path -LiteralPath $Latest)){return @{state='not_configured';id=''}}
 NoLinks $Root;Safe $Root;Safe $Latest
 $v=[IO.File]::ReadAllText($Latest,[Text.Encoding]::UTF8)|ConvertFrom-Json
 if($v.format -ne 1 -or $v.fixture -ne $Fixture -or $v.actor -cne $Actor -or $v.id -cnotmatch '^[a-f0-9]{32}$' -or $v.state -notin @('prepared','partial','committed','restored','rolled_back')){throw 'invalid receipt'}
 return $v
}
function Publish($r,$phase) {
 $r.state=$phase;$r.at_epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
 Save (Join-Path $Root ('record-'+$r.id+'.private.json')) $r $false
 $public=@{format=1;fixture=$Fixture;release='@RELEASE@';id=$r.id;actor=$r.actor;state=$r.state;roles=@('guard');at_epoch=$r.at_epoch;original=@(@{id='guard';definition_sha=$r.before.definition_sha;registered=$true;present=$true;enabled=$r.before.enabled;script_sha=$r.before.script_sha})}
 Save $Latest $public $true
 $log=Join-Path $Root ('events-'+[DateTime]::UtcNow.ToString('yyyy-MM-dd')+'.private.jsonl')
 if(-not(Test-Path -LiteralPath $log)){[IO.File]::WriteAllBytes($log,[byte[]]@());Protect $log $false $false};Safe $log
 $line=@{at_epoch=$r.at_epoch;transaction=$r.id;phase=$phase;role='guard'}|ConvertTo-Json -Compress
 $f=[IO.File]::Open($log,'Append','Write','Read');try{$bytes=[Text.Encoding]::UTF8.GetBytes($line+"`n");$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
'''

TRANSACTION = r'''
$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'administrator required'}
NoLinks $Root
foreach($dir in @((Split-Path -Parent $Root),$Root)){
 if(-not(Test-Path -LiteralPath $dir)){[IO.Directory]::CreateDirectory($dir)|Out-Null;Protect $dir $true $true};Safe $dir
}
$leasePath=Join-Path $Root '.transaction.lock'
if(-not(Test-Path -LiteralPath $leasePath)){[IO.File]::WriteAllBytes($leasePath,[byte[]]@());Protect $leasePath $false $false};Safe $leasePath
$lease=[IO.File]::Open($leasePath,'Open','ReadWrite','None')
$inputPath=Join-Path $Root ('.input-'+[guid]::NewGuid().ToString('N'))
function CheckScript($before) {
 NoLinks (Split-Path -Parent $Script)
 $f=Get-Item -LiteralPath $Script -Force
 if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -gt 1048576){throw 'script changed'}
 if((Get-FileHash -LiteralPath $Script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $before.script_sha){throw 'script changed'}
}
function Canonical([string]$body) {
 $xml=[xml]$body;$xml.PreserveWhitespace=$false
 $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
 $sd=$xml.SelectSingleNode('/t:Task/t:RegistrationInfo/t:SecurityDescriptor',$ns);if($sd){[void]$sd.ParentNode.RemoveChild($sd)}
 foreach($node in @($xml.SelectNodes('//t:UserId',$ns))){
  try{$node.InnerText=([Security.Principal.NTAccount]::new($node.InnerText)).Translate([Security.Principal.SecurityIdentifier]).Value}catch{[void][Security.Principal.SecurityIdentifier]::new($node.InnerText)}
 }
 return $xml.OuterXml
}
function Same($actual,$before,[bool]$exact) {
 if($actual.present -ne $true -or $actual.principal_sid -cne $Actor -or $actual.logon -ne 3 -or $actual.level -ne 0 -or $actual.secure_acl -ne $true -or $actual.enabled -ne $before.enabled -or $actual.sddl -cne $before.security){return $false}
 $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($before.definition))
 if($exact){return (Hash $actual.xml) -ceq $before.definition_sha}
 return (Canonical $actual.xml) -ceq (Canonical $xml)
}
function Restore($r) {
 CheckScript $r.before
 $live=ReadTask
 if($live.present){if(-not(Same $live $r.before $false)){throw 'later task change'}}else{
  $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r.before.definition))
  $service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\')
  [void]$folder.RegisterTask($TaskName,$xml,50,$Actor,$null,3,$r.before.security)
 }
 $live=ReadTask;if(-not(Same $live $r.before $false)){
  $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r.before.definition))
  throw ('restore readback; acl='+($live.sddl -ceq $r.before.security)+'; definition='+((Canonical $live.xml) -ceq (Canonical $xml)))
 }
 if($r.before.running -and $r.before.enabled){
  $service=New-Object -ComObject 'Schedule.Service';$service.Connect();[void]$service.GetFolder('\').GetTask($TaskName).Run($null)
  $until=[DateTime]::UtcNow.AddSeconds(10);do{$live=ReadTask;if($live.state -eq 4 -or $live.instances -gt 0){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $until)
  if($live.state -ne 4 -and $live.instances -eq 0){throw 'prior running state unverified'}
 }
}
try{
 [IO.File]::Copy(@INPUT@,$inputPath,$false);Protect $inputPath $false $false
 if((Get-Item -LiteralPath $inputPath).Length -gt 2097152 -or (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '@SHA@'){throw 'reviewed plan changed'}
 $plan=[IO.File]::ReadAllText($inputPath,[Text.Encoding]::UTF8)|ConvertFrom-Json
 if($plan.format -ne 1 -or $plan.actor -cne $Actor -or $plan.id -cnotmatch '^[a-f0-9]{32}$' -or @($plan.roles).Count -ne 1 -or $plan.roles[0] -cne 'guard'){throw 'invalid component plan'}
 $last=ReadLast
 if($last.id -cne $plan.expected_record){throw 'receipt changed'}
 if('@ACTION@' -ceq 'restore'){
  if($last.state -notin @('prepared','partial','committed')){throw 'nothing to restore'}
  $saved=Join-Path $Root ('record-'+$last.id+'.private.json');Safe $saved
  $r=[IO.File]::ReadAllText($saved,[Text.Encoding]::UTF8)|ConvertFrom-Json
  if($r.id -cne $last.id -or $r.actor -cne $Actor -or $r.fixture -ne $Fixture -or (Hash ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r.before.definition)))) -cne $r.before.definition_sha){throw 'original record invalid'}
  Publish $r 'prepared'
  try{Restore $r;Publish $r 'restored'}catch{Publish $r 'partial';throw}
 }else{
  if($last.state -in @('prepared','partial')){throw 'pending recovery'}
  if(Test-Path -LiteralPath (Join-Path $Root ('record-'+$plan.id+'.private.json'))){throw 'nonce reused'}
  $before=@($plan.before|Where-Object {$_.id -ceq 'guard'})
  if($before.Count -ne 1 -or $before[0].owned -ne $true -or $before[0].principal_sid -cne $Actor -or $before[0].script -cne $Script){throw 'invalid original identity'}
  $before=$before[0];$live=ReadTask
  if(-not(Same $live $before $true) -or ([bool]($live.state -eq 4 -or $live.instances -gt 0) -ne $before.running)){throw 'task changed'}
  CheckScript $before
  $r=@{format=1;fixture=$Fixture;release='@RELEASE@';id=$plan.id;actor=$Actor;roles=@('guard');state='prepared';before=$before;at_epoch=0}
  Publish $r 'prepared'
  try{
   $service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\');$task=$folder.GetTask($TaskName)
   if($before.running){$task.Stop(0)}
   $until=[DateTime]::UtcNow.AddSeconds(15)
   do{$live=ReadTask;if($live.state -ne 4 -and $live.instances -eq 0){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $until)
   if(-not(Same $live $before $true) -or $live.state -eq 4 -or $live.instances -gt 0){throw 'stop not verified'}
   CheckScript $before;$folder.DeleteTask($TaskName,0)
   $live=ReadTask;if($live.present -ne $false){throw 'removal not verified'}
   Publish $r 'committed'
  }catch{
   try{Restore $r;Publish $r 'rolled_back'}catch{Publish $r 'partial'}
   throw 'retirement not completed; inspect recovery'
  }
 }
}finally{
 if(Test-Path -LiteralPath $inputPath){Remove-Item -LiteralPath $inputPath -Force}
 $lease.Dispose()
}
'''


class WindowsComponents:
    def __init__(self, home, *, layout=None, runner=None, executable=None):
        self.layout = layout or Layout(home, 'Windows'); self.fixture = self.layout.fixture
        self.runner = runner or subprocess.run; self.executable = executable or powershell()
        self.actor = None

    def snapshot(self):
        value = windows_snapshot(self.layout, self.actor, runner=self.runner)
        if value.get('actor'): self.actor = value['actor']
        return value

    def _body(self, action, *, input_path=None, sha=None):
        if not self.actor or not re.fullmatch('S-1-[0-9-]+', self.actor): raise ValueError('组件用户身份未读取')
        root = quote(str(self.layout.root)) if self.fixture else "(Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EnvScope/components')"
        namespaces = ('Security.Principal', 'Security.AccessControl', 'Text', 'IO', 'Xml')
        def compact(source):
            for ns in namespaces: source = source.replace('['+ns+'.', '[')
            for old, new in (('before', 'b'), ('actual', 'a'), ('directory', 'd'), ('principal', 'p'), ('service', 'svc'), ('folder', 'tf')):
                source = re.sub(r'\$'+old+r'\b', '$'+new, source, flags=re.I)
            for old, new in (('NoLinks', 'L'), ('CheckScript', 'C'), ('ReadLast', 'J'), ('ReadTask', 'Q'),
                             ('Canonical', 'K'), ('Publish', 'P'), ('Protect', 'D'), ('Restore', 'R'),
                             ('Same', 'E'), ('Hash', 'H'), ('Safe', 'F'), ('Save', 'W')):
                source = re.sub(r'(?<![\w.])'+old+r'\b', 'x'+new, source)
            return source
        code = ''.join('using namespace System.'+ns+'\n' for ns in namespaces)
        code += "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[UTF8Encoding]::new($false)\n"
        code += "$env:PSModulePath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/Modules'\n"
        code += '$Actor='+quote(self.actor)+';$Fixture='+('$true' if self.fixture else '$false')+';$Root='+root+'\n'
        code += "$Latest=Join-Path $Root 'latest.json';$TaskName="+quote(self.layout.task)+';$Script='+quote(str(self.layout.script('guard')))+'\n'
        code += compact(PROTECT).replace('@RELEASE@', __release__)
        if action == 'status': return code+compact('\nReadLast|ConvertTo-Json -Depth 12 -Compress\n')
        if action not in ('retire', 'restore') or not re.fullmatch('[a-f0-9]{64}', sha or ''): raise ValueError('组件修改参数无效')
        read = compact(WINDOWS_READ).replace('@TASK@', quote(self.layout.task)).replace('@ACTOR@', quote(self.actor))
        code += compact('\nfunction ReadTask { $data=& {\n')+read+'\n};return ($data|ConvertFrom-Json) }\n'
        return code+compact(TRANSACTION).replace('@RELEASE@', __release__).replace('@ACTION@', action).replace('@INPUT@', quote(input_path)).replace('@SHA@', sha)

    def status(self):
        if not self.actor: self.snapshot()
        value = self.runner([self.executable, '-NoProfile', '-NonInteractive', '-Command', self._body('status')],
                            capture_output=True, timeout=10, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if value.returncode or len(value.stdout) > 1024*1024: raise ValueError('旧组件恢复记录读取失败，请核对权限')
        data = json.loads(value.stdout.decode('utf-8-sig') if isinstance(value.stdout, bytes) else value.stdout)
        if not isinstance(data, dict): raise ValueError('旧组件恢复记录格式不符')
        return data

    def execute(self, action, payload):
        raw = json.dumps(payload, ensure_ascii=True).encode()
        with tempfile.TemporaryDirectory(prefix='envscope-components-plan-') as folder:
            path = Path(folder).resolve()/'plan.private.bin'; path.write_bytes(raw)
            body = self._body(action, input_path=path, sha=hashlib.sha256(raw).hexdigest())
            body = '\n'.join(line.lstrip() for line in body.splitlines() if line.strip())
            encoded = base64.b64encode(body.encode('utf-16-le')).decode()
            if (len(encoded) > 31800 or len(subprocess.list2cmdline([self.executable, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded])) > 32000):
                raise ValueError('旧组件操作超过系统命令长度，未执行')
            launcher = ("$ErrorActionPreference='Stop';$code=[Console]::In.ReadToEnd();"
                "if($code.Length -gt 31800 -or $code -cnotmatch '^[A-Za-z0-9+/=]+$'){exit 65};"
                "$o=@{FilePath="+quote(self.executable)+";ArgumentList=@('-NoProfile','-NonInteractive','-EncodedCommand',$code);WindowStyle='Hidden';Wait=$true;PassThru=$true};"
                "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());"
                "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){$o.Verb='RunAs'};"
                "$v=Start-Process @o;exit $v.ExitCode")
            result = self.runner([self.executable, '-NoProfile', '-NonInteractive', '-Command', launcher], input=encoded.encode(),
                                 capture_output=True, timeout=150, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if result.returncode: raise ValueError('系统授权取消或旧组件操作未完成，请核对受保护的恢复记录')
