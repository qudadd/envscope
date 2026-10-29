"""Actual CFPreferences transactions only in a unique CI-owned app domain."""
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import uuid

from envscope import __release__
from envscope.language_repair import LanguageIO,LanguageRepair
from envscope.mac_preferences import ClaudePreferences,HOSTS
from envscope.state import StateStore
from envscope.target_environment import fingerprint


def main():
    if platform.system()!='Darwin':print('SKIP: CFPreferences is macOS-only');return
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('ENVSCOPE_CLIENT_ACCEPTANCE')!='1':
        raise SystemExit('Refusing preference acceptance outside opted-in disposable CI')
    domain='io.qudadd.envscope.fixture.'+uuid.uuid4().hex
    prefs=ClaudePreferences(fixture_domain=domain);reference=prefs.reference();before=prefs.read()
    assert not any(before[h]['present'] for h in HOSTS),'Fixture domain must be fresh'
    def child():
        code='import json,sys;from envscope.mac_preferences import ClaudePreferences;print(json.dumps(ClaudePreferences(fixture_domain=sys.argv[1]).read()))'
        return json.loads(subprocess.run([sys.executable,'-c',code,domain],check=True,capture_output=True,text=True,timeout=15).stdout)
    try:
        with tempfile.TemporaryDirectory() as folder:
            store=StateStore(Path(folder).resolve()/'state');store.save_settings({'usage':'desktop','connection_mode':'direct','usage_country':'US','language':'ja-JP'},confirm_environment=True)
            io=LanguageIO(backend=prefs,close_desktop=lambda:True,available=True);manager=LanguageRepair(store,io)
            report={'created_at':datetime.now(timezone.utc).isoformat(),'mode':'one-click-desktop','diagnosis':{},
                    'environment':{'fingerprint':fingerprint(store.settings())},'findings':[{'id':'target.region','status':'pass'}]}
            def exercise():
                original=prefs.read();plan=manager.prepare(report);assert plan['state']=='planned',plan
                assert prefs.read()==original,'Preview wrote preferences'
                assert manager.apply(plan['plan_id'],1)['state']=='confirmation_required'
                result=manager.apply(plan['plan_id'],True);assert result['state']=='completed',result
                independent=child();assert independent==prefs.read() and independent['effective']['value']==['ja-JP'],'Independent readback failed'
                restart=LanguageRepair(store,io);restore=restart.prepare_restore();assert restore['state']=='planned',restore
                assert restart.restore(restore['plan_id'],True)['state']=='completed'
                assert child()==original,'Restoration lost typed values or missing keys'
                assert prefs.reference()==reference,'Real Claude or global preferences changed'
            exercise()
            absent={'present':False,'value':None}
            prefs.set_host('any',{'present':True,'value':['zh-Hans-CN','en']},absent)
            prefs.set_host('current',{'present':True,'value':['fr-FR','en-US']},absent)
            exercise()
    finally:
        for host in HOSTS:
            current=prefs.read()[host]
            if current['present']:prefs.set_host(host,{'present':False,'value':None},current)
        assert child()==before and prefs.reference()==reference,'Cleanup or reference readback failed'
    result={'release':__release__,'platform':platform.system(),'architecture':platform.machine(),'fixture':True,
            'typed_absence_and_arrays':True,'byhost_precedence':True,'independent_process_readback':True,
            'restart_recovery':True,'real_claude_unchanged':True,'global_preferences_unchanged':True,'fixture_keys_removed':True,
            'actual_claude_ui_language_tested':False}
    output=Path('artifacts/language-acceptance');output.mkdir(parents=True,exist_ok=True)
    (output/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))


if __name__=='__main__':main()
