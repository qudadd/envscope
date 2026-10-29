"""Root one-shot fixture; production network settings are read only before/after."""
import base64
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shlex
import subprocess
import tempfile
import uuid

from envscope.state import StateStore
from envscope.system_network import SystemNetwork,binding_view,signature,validate_snapshot
from envscope.system_network_macos import MacNetworkIO
from envscope.target_environment import fingerprint
from envscope.timezone_service import Layout
from scripts.build_timezone_worker import build


def sudo(script,check=True):
    value=subprocess.run(['/usr/bin/sudo','-n','/bin/sh'],input=script,text=True,capture_output=True,timeout=150)
    if check and value.returncode:raise RuntimeError('Owned network fixture failed: '+value.stderr[-1200:])
    return value


def main():
    if platform.system()!='Darwin' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('ENVSCOPE_NETWORK_ACCEPTANCE')!='1':
        raise SystemExit('Network root fixtures require explicit disposable macOS CI opt-in')
    output=Path('artifacts/network-acceptance');output.mkdir(parents=True,exist_ok=True)
    nonce=uuid.uuid4().hex[:12]
    root=Path('/Library/PrivilegedHelperTools')/('io.qudadd.envscope.network.ci-'+nonce)
    layout=Layout(root,Path('/Library/LaunchDaemons')/('unused.'+nonce+'.plist'),'io.qudadd.envscope.network.ci-'+nonce)
    production=build(component='network')
    prod=production/'network-helper'
    actual=validate_snapshot(plistlib.loads(subprocess.check_output([str(prod),'--snapshot'])))
    actual_before=binding_view(actual,{r['id'] for r in actual['adapters']})
    phases=[]
    proof={'platform':'Darwin','architecture':platform.machine(),'fixture':True,'real_network_changed':False,
           'real_dns_cache_flushed':False,'production_service_installed':False,'state':'started'}
    try:
        with tempfile.TemporaryDirectory(prefix='envscope-network-acceptance-') as folder:
            folder=Path(folder).resolve()
            header=folder/'fixture.h'
            header.write_text('#define ENVSCOPE_NET_ROOT '+json.dumps(str(root))+'\n#define ENVSCOPE_NET_FIXTURE 1\n')
            built=build(folder/'native',header,component='network')
            worker={'path':str(built/'network-helper'),'sha256':hashlib.sha256((built/'network-helper').read_bytes()).hexdigest()}
            symbols=subprocess.check_output(['/usr/bin/nm','-u',worker['path']],text=True)
            assert 'SCPreferencesCommitChanges' not in symbols and 'SCNetworkProtocolSetEnabled' not in symbols
            assert b'/usr/bin/dscacheutil' not in (built/'network-helper').read_bytes()
            proof['fixture_has_no_system_write_symbols']=True
            initial={'adapters':[
                {'id':'11111111-1111-4111-8111-111111111111','name':"Fixture A ' $() 中文",'active':True,'ipv6_enabled':True,
                 'config':{'ConfigMethod':'Manual','Addresses':['2001:db8::1'],'PrefixLength':[64],'Opaque':b'CF_DATA_FIXTURE'}},
                {'id':'22222222-2222-4222-8222-222222222222','name':'Fixture B','active':True,'ipv6_enabled':True,
                 'config':{'ConfigMethod':'Automatic'}}]}
            data=base64.b64encode(plistlib.dumps(initial)).decode()
            setup='set -eu\n/bin/mkdir '+shlex.quote(str(root))+'\n/bin/chmod 755 '+shlex.quote(str(root))+'\n'
            setup+='/usr/bin/printf %s '+shlex.quote(data)+' | /usr/bin/base64 -D > '+shlex.quote(str(root/'fixture.plist'))+'\n/bin/chmod 644 '+shlex.quote(str(root/'fixture.plist'))+'\n'
            sudo(setup)
            class FixtureIO(MacNetworkIO):
                def execute(self,action,payload):
                    content=plistlib.dumps(payload,sort_keys=True);path=folder/'plan.private.bin';path.write_bytes(content)
                    result=sudo(self.script(action,path,hashlib.sha256(content).hexdigest(),worker),False)
                    if result.returncode:raise ValueError('Injected network operation returned '+str(result.returncode))
            io=FixtureIO(layout=layout,worker=lambda:worker,fixture=True)
            store=StateStore(folder/'state')
            store.save_settings({'usage':'desktop','connection_mode':'tun','usage_country':'US','country':'US',
                                 'timezone':'America/New_York','locale':'en-US','ipv6_mode':'disabled'},confirm_environment=True)
            report={'report_id':'native-fixture','mode':'one-click-desktop','created_at':datetime.now(timezone.utc).isoformat(),
                    'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],
                    'environment':{'fingerprint':fingerprint(store.settings())}}
            manager=SystemNetwork(store,io)
            original=io.snapshot()
            plan=manager.prepare(report,flush_dns=True);assert plan['state']=='planned'
            assert manager.apply(plan['plan_id'],1)['state']=='confirmation_required'
            assert manager.apply(plan['plan_id'],True)['state']=='completed'
            assert all(not r['ipv6_enabled'] for r in io.snapshot()['adapters']);phases.append('applied_and_read_back')
            json.dumps(manager.options())
            mode=sudo('/usr/bin/stat -f %u:%Lp '+shlex.quote(str(root/('record-'+io.status()['id']+'.private.plist')))).stdout.strip()
            assert mode=='0:600';proof['root_private_backup']=True
            restore=manager.prepare_restore();assert manager.restore(restore['plan_id'],True)['state']=='completed'
            assert io.snapshot()==original;phases.append('full_original_configuration_restored')
            # Actual process interruption after the fixture storage commit.
            sudo('/usr/bin/touch '+shlex.quote(str(root/'interrupt-after-commit')))
            plan=manager.prepare(report);assert manager.apply(plan['plan_id'],True)['state']=='partial'
            assert io.status()['state']=='prepared'
            sudo('/bin/rm -f '+shlex.quote(str(root/'interrupt-after-commit')))
            restore=manager.prepare_restore();assert manager.restore(restore['plan_id'],True)['state']=='completed'
            assert io.snapshot()==original;phases.append('interrupted_commit_recovered')
            # DNS failure retains reversible network state and a clear receipt.
            sudo('/usr/bin/touch '+shlex.quote(str(root/'fail-dns')))
            plan=manager.prepare(report,flush_dns=True);assert manager.apply(plan['plan_id'],True)['state']=='partial'
            assert io.status()['state']=='partial' and io.status()['dns_flush']=='unverified'
            sudo('/bin/rm -f '+shlex.quote(str(root/'fail-dns')))
            restore=manager.prepare_restore();assert manager.restore(restore['plan_id'],True)['state']=='completed'
            assert io.snapshot()==original;phases.append('dns_failure_has_recoverable_receipt')
            # A backend rejection cannot be reported as a repaired setting.
            sudo('/usr/bin/touch '+shlex.quote(str(root/'fail-set')))
            plan=manager.prepare(report);assert manager.apply(plan['plan_id'],True)['state']=='partial'
            assert io.status()['state']=='rolled_back' and io.snapshot()==original
            sudo('/bin/rm -f '+shlex.quote(str(root/'fail-set')));phases.append('failed_set_rolled_back')
            # DNS-only work must not rewrite even the fixture's network settings.
            before=(root/'fixture.plist').stat().st_mtime_ns
            plan=manager.prepare(report,adapter_ids=[],flush_dns=True)
            assert manager.apply(plan['plan_id'],True)['state']=='completed'
            assert (root/'fixture.plist').stat().st_mtime_ns==before;phases.append('dns_only_has_no_network_rewrite')
            proof.update(state='passed',phases=phases,configuration_readback=True,original_configuration_preserved=True,
                         interrupted_recovery=True,failed_write_rollback=True,dns_failure_visible=True,dns_only_is_scoped=True)
            (output/'fixture-events.txt').write_text('\n'.join(p.read_text() for p in root.glob('*.private.jsonl')))
    finally:
        assert root.parent==Path('/Library/PrivilegedHelperTools') and root.name=='io.qudadd.envscope.network.ci-'+nonce
        sudo('/bin/rm -rf '+shlex.quote(str(root)),False)
        actual_after=validate_snapshot(plistlib.loads(subprocess.check_output([str(prod),'--snapshot'])))
        proof['real_network_changed']=binding_view(actual_after,{r['id'] for r in actual_after['adapters']})!=actual_before
        assert not proof['real_network_changed'] and not root.exists()
        proof['fixture_removed']=True
        (output/'result.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()
