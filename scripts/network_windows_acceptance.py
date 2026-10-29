"""Actual Windows root ACL/transport/receipts, with filesystem-only fake bindings."""
from datetime import datetime,timezone
import base64
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import uuid

from envscope.state import StateStore
from envscope.system_network import SystemNetwork,binding_view
from envscope.system_network_windows import WindowsNetworkIO,powershell,quote,script
from envscope.target_environment import fingerprint


def main():
    if platform.system()!='Windows' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('ENVSCOPE_NETWORK_ACCEPTANCE')!='1':
        raise SystemExit('Windows network fixture requires opted-in disposable CI')
    ps=powershell()
    def run(body,check=True):
        value=subprocess.run([ps,'-NoProfile','-NonInteractive','-Command',body],capture_output=True,timeout=30,
                             creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if check and value.returncode:raise RuntimeError('Owned Windows fixture failed: '+value.stderr.decode('utf-8',errors='replace')[-1600:])
        return value
    assert run("$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 77}",False).returncode==0
    # Production path is read-only. No production write command is evaluated.
    real=WindowsNetworkIO(executable=ps)
    before=real.snapshot();actual_before=binding_view(before,{r['id'] for r in before['adapters']})
    common=Path(run("[Console]::Write([Environment]::GetFolderPath('CommonApplicationData'))").stdout.decode())
    nonce=uuid.uuid4().hex[:12];base=(common/('EnvScopeNetworkAcceptance-'+nonce)).resolve();root=base/'network'
    state={'format':1,'owner':before['owner'],'adapters':[
        {'id':'11111111-1111-4111-8111-111111111111','name':"Fixture ' [A] $() 中文",'active':True,'ipv6_enabled':True,'config':{'ms_tcpip':True,'fixture_filter':False}},
        {'id':'22222222-2222-4222-8222-222222222222','name':'Fixture B','active':True,'ipv6_enabled':True,'config':{'ms_tcpip':True}}]}
    encoded=base64.b64encode(json.dumps(state).encode()).decode()
    backend=r'''
function Read-Network {
 $file=Join-Path $Root 'fixture.json'
 if(-not(Test-Path -LiteralPath $file)) {[IO.File]::WriteAllBytes($file,[Convert]::FromBase64String('@INITIAL@'))}
 return ([IO.File]::ReadAllText($file,[Text.Encoding]::UTF8) | ConvertFrom-Json)
}
function Write-V6($id,[bool]$enabled) {
 if(Test-Path -LiteralPath (Join-Path $Root 'fail-set')){throw 'fixture setter failure'}
 $data=Read-Network;$row=@($data.adapters | Where-Object {$_.id -ceq $id})[0]
 $row.ipv6_enabled=$enabled
 [IO.File]::WriteAllText((Join-Path $Root 'fixture.json'),($data | ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
 if(Test-Path -LiteralPath (Join-Path $Root 'interrupt-after-set')){exit 137}
}
function Flush-Dns {
 if(Test-Path -LiteralPath (Join-Path $Root 'fail-dns')){throw 'fixture cache failure'}
 [IO.File]::WriteAllText((Join-Path $Root 'fixture-dns'),[DateTime]::UtcNow.Ticks)
}
'''.replace('@INITIAL@',encoded)
    def body(mode,**kwargs):return script(mode,fixture_root=root,fixture_backend=backend,**kwargs)
    assert 'Get-NetAdapter' not in body('snapshot') and 'Clear-DnsClientCache' not in body('snapshot')
    proof={'platform':'Windows','architecture':platform.machine(),'fixture':True,'real_network_changed':False,
           'real_dns_cache_flushed':False,'actual_admin_dialogs':0,'state':'started'}
    output=Path('artifacts/network-windows-acceptance');output.mkdir(parents=True,exist_ok=True)
    phases=[]
    try:
        bootstrap=body('status').removesuffix('Read-Record | ConvertTo-Json -Depth 30 -Compress\n')
        bootstrap+='\nforeach($directory in @((Split-Path -Parent $Root),$Root)){[IO.Directory]::CreateDirectory($directory) | Out-Null;Protect $directory $true $true}\n'
        run(bootstrap)
        class FixtureIO(WindowsNetworkIO):
            def _body(self,mode,**kwargs):return body(mode,**kwargs)
        io=FixtureIO(executable=ps);io.fixture=True
        original=io.snapshot()
        with tempfile.TemporaryDirectory(prefix='envscope-network-windows-') as folder:
            store=StateStore(Path(folder))
            store.save_settings({'usage':'desktop','connection_mode':'tun','usage_country':'US','country':'US',
                                 'timezone':'Eastern Standard Time','locale':'en-US','ipv6_mode':'disabled'},confirm_environment=True)
            manager=SystemNetwork(store,io)
            def report():return {'report_id':'windows-native-fixture','mode':'one-click-desktop','created_at':datetime.now(timezone.utc).isoformat(),
                                'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],
                                'environment':{'fingerprint':fingerprint(store.settings())}}
            plan=manager.prepare(report(),flush_dns=True)
            assert manager.apply(plan['plan_id'],True)['state']=='completed'
            assert all(not r['ipv6_enabled'] for r in io.snapshot()['adapters']);phases.append('applied_and_read_back')
            # Private history is protected, while ordinary UI can read latest metadata.
            ident=io.status()['id'];private=root/('record-'+ident+'.private.json')
            acl=json.loads(run("$a=Get-Acl -LiteralPath "+quote(private)+";@{owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;protected=$a.AreAccessRulesProtected;users=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-5-32-545'}).Count}|ConvertTo-Json -Compress").stdout)
            assert acl['owner']=='S-1-5-32-544' and acl['protected'] and acl['users']==0;proof['root_private_backup']=True
            restore=manager.prepare_restore();assert manager.restore(restore['plan_id'],True)['state']=='completed'
            assert io.snapshot()==original;phases.append('original_bindings_restored')
            run('[IO.File]::WriteAllText('+quote(root/'interrupt-after-set')+",'fixture')")
            plan=manager.prepare(report());assert manager.apply(plan['plan_id'],True)['state']=='partial'
            assert io.status()['state']=='prepared'
            run('Remove-Item -LiteralPath '+quote(root/'interrupt-after-set'))
            restore=manager.prepare_restore();assert manager.restore(restore['plan_id'],True)['state']=='completed'
            assert io.snapshot()==original;phases.append('interrupted_process_recovered')
            run('[IO.File]::WriteAllText('+quote(root/'fail-dns')+",'fixture')")
            plan=manager.prepare(report(),flush_dns=True);assert manager.apply(plan['plan_id'],True)['state']=='partial'
            assert io.status()['dns_flush']=='unverified'
            run('Remove-Item -LiteralPath '+quote(root/'fail-dns'))
            restore=manager.prepare_restore();assert manager.restore(restore['plan_id'],True)['state']=='completed'
            assert io.snapshot()==original;phases.append('cache_failure_is_visible_and_recoverable')
            run('[IO.File]::WriteAllText('+quote(root/'fail-set')+",'fixture')")
            plan=manager.prepare(report());assert manager.apply(plan['plan_id'],True)['state']=='partial'
            assert io.status()['state']=='rolled_back' and io.snapshot()==original
            run('Remove-Item -LiteralPath '+quote(root/'fail-set'));phases.append('failed_write_rolled_back')
        proof.update(state='passed',phases=phases,configuration_readback=True,original_configuration_preserved=True,
                     interrupted_recovery=True,failed_write_rollback=True,dns_failure_visible=True)
    finally:
        after=real.snapshot();proof['real_network_changed']=binding_view(after,{r['id'] for r in after['adapters']})!=actual_before
        assert not proof['real_network_changed']
        assert base.parent==common.resolve() and base.name=='EnvScopeNetworkAcceptance-'+nonce
        run('Remove-Item -LiteralPath '+quote(base)+' -Recurse -Force',False)
        assert not base.exists();proof['fixture_removed']=True
        (output/'result.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
