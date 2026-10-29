"""Typed preferences and recovery; writes stay in a disposable fake backend."""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from envscope.language_repair import LanguageIO,LanguageRepair
from envscope.mac_preferences import DOMAIN,HOSTS,ClaudePreferences,validate_model,validate_snapshot,read_claude_language
from envscope.model import make_report
from envscope.operations import Operations
from envscope.state import StateStore
from envscope.target_environment import fingerprint
from scripts.environment_fixtures import fixture,fixture_policy

ABSENT={'present':False,'value':None}
def present(*values):return {'present':True,'value':list(values)}
class Interrupted(BaseException):pass


class PreferenceFixture:
    domain=DOMAIN
    def __init__(self):
        self.values={h:deepcopy(ABSENT) for h in HOSTS};self.fallback=['zh-Hans-CN'];self.forced=False
        self.writes=[];self.fail=False;self.crash=False;self.manage=False
    def read(self):
        value=deepcopy(self.values)
        value['effective']=deepcopy(value['current'] if value['current']['present'] else value['any'] if value['any']['present'] else present(*self.fallback))
        value['forced']=self.forced;return validate_snapshot(value)
    def set_host(self,host,model,expected):
        validate_model(model);validate_model(expected)
        if self.values[host]!=expected or self.forced:raise ValueError('fixture preference changed / managed')
        self.values[host]=deepcopy(model);self.writes.append((host,deepcopy(model)))
        if self.crash:self.crash=False;raise Interrupted()
        if self.fail:
            self.fail=False
            if self.manage:self.forced=True
            raise ValueError('fixture sync failed after write')


class LanguageFixtureIO(LanguageIO):
    def __init__(self,backend=None):
        self.closes=0;self.close_ok=True
        super().__init__(backend=backend or PreferenceFixture(),close_desktop=self.close,available=True)
    def close(self):self.closes+=1;return self.close_ok
    def actor(self):return 'fixture-owner'


class LanguageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name).resolve()
        self.store=StateStore(self.home/'state')
        self.store.save_settings({'usage':'desktop','connection_mode':'direct','usage_country':'US','language':'ja-JP'},confirm_environment=True)
        self.io=LanguageFixtureIO();self.prefs=self.io.backend();self.seconds=0
        self.manager=LanguageRepair(self.store,self.io,clock=lambda:self.seconds)
        self.report={'created_at':datetime.now(timezone.utc).isoformat(),'report_id':'fixture-language-report','mode':'one-click-desktop','diagnosis':{},
            'findings':[{'id':'target.region','status':'pass'}],'environment':{'fingerprint':fingerprint(self.store.settings())}}
    def plan(self):
        value=self.manager.prepare(self.report);self.assertEqual(value['state'],'planned',value);return value
    def apply(self):
        value=self.plan();result=self.manager.apply(value['plan_id'],True);self.assertEqual(result['state'],'completed',result);return result

    def test_confirmation_read_only_preview_and_undo_preserve_absence(self):
        before=self.io.snapshot();plan=self.plan()
        self.assertIn('ja-JP',str(plan['effects']));self.assertEqual(self.prefs.writes,[]);self.assertEqual(self.io.closes,0)
        self.assertFalse(self.manager.root.exists())
        for value in (False,1,'true',None):self.assertEqual(self.manager.apply(plan['plan_id'],value)['state'],'confirmation_required')
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'completed')
        self.assertEqual(self.prefs.values['any'],present('ja-JP'));self.assertEqual(self.prefs.values['current'],ABSENT)
        restarted=LanguageRepair(self.store,self.io,clock=lambda:self.seconds)
        restore=restarted.prepare_restore();self.assertEqual(restore['state'],'planned')
        self.assertEqual(restarted.restore(restore['plan_id'],True)['state'],'completed')
        self.assertEqual(self.io.snapshot(),before);self.assertEqual(restarted.status()['state'],'rolled_back')

    def test_multiple_languages_byhost_and_empty_arrays_are_restored_exactly(self):
        for current in (present('fr-FR','en-US'),present()):
            self.prefs.values={'any':present('zh-Hans-CN','en'),'current':current};before=self.io.snapshot();self.apply()
            self.assertEqual(self.prefs.values['current'],present('ja-JP'))
            restore=self.manager.prepare_restore();self.manager.restore(restore['plan_id'],True)
            self.assertEqual(self.io.snapshot(),before)

    def test_failed_sync_rolls_back_and_managed_change_remains_pending(self):
        self.prefs.fail=True;plan=self.plan();result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['state'],'partial');self.assertEqual(result['recovery']['state'],'completed')
        self.assertEqual(self.prefs.values['any'],ABSENT)
        self.prefs.fail=self.prefs.manage=True;plan=self.plan();result=self.manager.apply(plan['plan_id'],True)
        self.assertEqual(result['recovery']['state'],'partial');self.assertEqual(self.manager.status()['state'],'partial')
        self.assertEqual(self.manager.prepare(self.report)['state'],'guided');self.assertEqual(self.manager.prepare_restore()['state'],'guided')

    def test_actual_interruption_is_recoverable_after_service_restart(self):
        self.prefs.values['current']=present('fr-FR');before=self.io.snapshot();plan=self.plan();self.prefs.crash=True
        with self.assertRaises(Interrupted):self.manager.apply(plan['plan_id'],True)
        restarted=LanguageRepair(self.store,self.io,clock=lambda:self.seconds)
        self.assertEqual(restarted.status()['state'],'writing');self.assertEqual(restarted.prepare(self.report)['state'],'guided')
        restore=restarted.prepare_restore();self.assertEqual(restore['state'],'planned')
        self.assertEqual(restarted.restore(restore['plan_id'],True)['state'],'completed');self.assertEqual(self.io.snapshot(),before)

    def test_later_app_edits_and_changed_preview_are_not_overwritten(self):
        plan=self.plan();self.prefs.values['any']=present('de-DE')
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required');self.assertEqual(self.io.closes,0)
        self.apply();restore=self.manager.prepare_restore();self.prefs.values['any']=present('fr-CA')
        self.assertEqual(self.manager.restore(restore['plan_id'],True)['state'],'retest_required')
        self.assertEqual(self.manager.prepare_restore()['state'],'guided');self.assertEqual(self.prefs.values['any'],present('fr-CA'))

    def test_undo_absent_key_respects_a_new_system_fallback(self):
        self.apply();self.prefs.fallback=['de-DE'];restore=self.manager.prepare_restore()
        self.assertEqual(self.manager.restore(restore['plan_id'],True)['state'],'completed')
        self.assertEqual(self.io.snapshot()['effective'],present('de-DE'));self.assertEqual(self.prefs.values['any'],ABSENT)

    def test_exit_declined_stale_target_region_or_corrupt_backup_cannot_authorize_writes(self):
        self.io.close_ok=False;plan=self.plan()
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'guided');self.assertFalse(self.prefs.writes)
        self.io.close_ok=True;plan=self.plan();self.seconds=91
        self.assertEqual(self.manager.apply(plan['plan_id'],True)['state'],'retest_required')
        old=deepcopy(self.report);old['created_at']=(datetime.now(timezone.utc)-timedelta(seconds=100)).isoformat()
        self.assertEqual(self.manager.prepare(old)['state'],'guided')
        self.store.save_settings({'usage_country':'CN'},confirm_environment=True);self.report['environment']['fingerprint']=fingerprint(self.store.settings())
        self.assertEqual(self.manager.prepare(self.report)['state'],'guided')
        self.store.save_settings({'usage_country':'US'},confirm_environment=True);self.report['environment']['fingerprint']=fingerprint(self.store.settings())
        self.apply();record=self.manager._record();(self.manager.root/record['id']/'before.private.json').write_bytes(b'corrupt fixture')
        self.assertEqual(self.manager.status()['state'],'invalid');self.assertEqual(self.manager.prepare_restore()['state'],'guided')

    def test_unknown_types_and_managed_preferences_are_never_coerced(self):
        for model in ({'present':True,'value':'en-US'},{'present':False,'value':[]},{'present':1,'value':None},{'present':True,'value':[1]}):
            with self.assertRaises(ValueError):validate_model(model)
        self.prefs.forced=True;self.assertEqual(self.manager.prepare(self.report)['state'],'guided');self.assertEqual(self.prefs.writes,[])
        with patch('envscope.mac_preferences.ClaudePreferences',return_value=self.prefs):
            self.prefs.forced=False;self.assertEqual(read_claude_language()['source'],'application-fallback')
            self.prefs.values['current']=present('fr-FR');self.assertEqual(read_claude_language()['value'],'fr-FR')

    def test_fixture_domain_is_not_a_public_input_or_local_bypass(self):
        with patch('envscope.mac_preferences.platform.system',return_value='Darwin'),patch.dict('os.environ',{'GITHUB_ACTIONS':'false'}):
            with self.assertRaises(ValueError):ClaudePreferences(fixture_domain='io.qudadd.envscope.fixture.'+'a'*32)
        ops=Operations(self.store,self.home,discoverer=lambda:[],language_repair=self.manager)
        for key in ('domain','key','language','user','host','path','command'):
            with self.assertRaises(ValueError):ops.run('language-plan',{'report_id':self.report['report_id'],key:'unexpected'},report=self.report)

    def test_selected_checks_write_only_the_confirmed_app_language(self):
        settings=self.store.settings();rows=fixture(self.home,settings,'Darwin')
        report=make_report(rows,fixture_policy(settings),'one-click-desktop',settings)
        ops=Operations(self.store,self.home,discoverer=lambda:[],language_repair=self.manager)
        plan=ops.solutions.prepare(report,check_ids=['baseline.language'])
        self.assertEqual(plan['state'],'planned',plan);self.assertFalse(self.prefs.writes)
        self.assertEqual(ops.solutions.apply(plan['plan_id'],report,True)['state'],'executed')
        self.assertEqual(self.prefs.values['any'],present('ja-JP'));self.assertEqual(self.prefs.fallback,['zh-Hans-CN'])


if __name__=='__main__':unittest.main()
