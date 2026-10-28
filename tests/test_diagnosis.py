"""Evidence-based problem interpretation, fixed edits and the complete local API flow."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.request import Request, ProxyHandler, build_opener

from envscope.config_files import inspect_text, remove_trailing_commas
from envscope.diagnosis import diagnose, compare_diagnoses
from envscope.local_facts import config_shape, cli_facts, bypass_matches
from envscope.model import Finding, Status, make_report
from envscope.operations import Operations
from envscope.policy import Policy
from envscope.remedies import ConfigRemedies, SolutionPlans
from envscope.report import redact, html_report
from envscope.service import make_server
from envscope.state import StateStore
from envscope.transport import CurlTransport, MARKER, application_state
import subprocess


def finding(key, state="unknown", entries=(), summary="fixture"):
    return Finding(key, key, Status(state), summary, "test-fixture", list(entries))


def report_with(*findings, preferences=None):
    rows = list(findings)
    if not any(f.id == 'baseline.country' for f in rows):
        rows.append(finding('baseline.country','warn',[{'actual':'US','expected':''}]))
    return make_report(rows, Policy(), "one-click-desktop", {'usage_country':'US', **(preferences or {})})


def response(code=401, error="", host="api.anthropic.com"):
    return {"endpoint": "https://" + host + ("/v1/models" if host.startswith("api.") else "/"),
            "http_status": code, "error": error, "tls_verified": not bool(error)}


class DiagnosisTests(unittest.TestCase):
    def test_anonymous_401_is_explained_without_inventing_account_failure(self):
        value = report_with(finding("baseline.reachability", "pass", [response()]))["diagnosis"]
        self.assertEqual(value["state"], "responding")
        self.assertFalse(value["problems"])
        self.assertIn("未发送密钥", "".join(value["normal"]))
        self.assertIn("不能据此确认账号", value["summary"])

    def test_403_does_not_diagnose_a_ban(self):
        value = report_with(finding("baseline.reachability", "warn", [response(403)]))["diagnosis"]
        self.assertEqual(len(value["problems"]), 1)
        self.assertIn("不能判断封禁原因", value["problems"][0]["cause"])
        self.assertEqual(value["problems"][0]["action"], "claude-web")

    def test_rate_limit_and_server_failures_do_not_trigger_local_reinstall(self):
        for number in (429, 500, 503, 529):
            r = response(number)
            r["retry_after_seconds"] = 50
            value = report_with(finding("baseline.reachability", "warn", [r]))["diagnosis"]["problems"][0]
            self.assertIsNone(value["repair"])
            self.assertEqual(value["action"], "service-status")
            self.assertNotIn("重装", " ".join(value["steps"]).replace("不靠重装软件解决", ""))
            if number == 429:
                self.assertIn("50 秒", value["steps"][0])

    def test_transport_stages_have_distinct_explanations(self):
        expected = {5:"network.proxy_dns", 6:"network.dns", 7:"network.connect", 28:"network.timeout", 35:"network.handshake", 60:"network.certificate", 77:"network.certificate"}
        for number, key in expected.items():
            value = report_with(finding("baseline.reachability", "unknown", [response(0, "curl_exit_"+str(number))]))["diagnosis"]
            self.assertIn(key, [p["id"] for p in value["problems"]])

    def test_closed_proxy_supersedes_secondary_connection_symptoms(self):
        value = report_with(finding("extra.proxy_listener", "warn", [{"tcp_accepts": False}]),
                            finding("baseline.reachability", "unknown", [response(0,"curl_exit_7")]))["diagnosis"]
        self.assertEqual([p["id"] for p in value["problems"]], ["proxy.listener"])
        self.assertIn("端口", value["summary"])

    def test_clock_skew_comes_before_certificate_repair_without_asserting_cause(self):
        value = report_with(finding("extra.clock", "warn", [{"offset_seconds": 500,"sample_count":2}]),
                            finding("extra.tls", "fail"))["diagnosis"]
        self.assertEqual([p["id"] for p in value["problems"]], ["clock.offset"])
        self.assertIn("可能", value["problems"][0]["cause"])

    def test_nan_date_and_unknowns_cannot_become_a_clear_result(self):
        value = report_with(finding("extra.clock", "unknown", [{"offset_seconds": float("nan")}]),
                            finding("dns.leak"), finding("network.route"))["diagnosis"]
        self.assertEqual(value["state"], "unavailable")
        self.assertFalse(value["problems"])
        self.assertTrue(all(c["state"] == "unsupported" for c in value["checks"] if c["id"] in ("dns.leak","network.route")))

    def test_optional_preferences_do_not_hide_an_unsupported_exit(self):
        value = report_with(finding("baseline.country", "warn", [{"actual":"CN","expected":""}]),
                            finding("extra.target_route", "warn"), finding("extra.runtime_tun", "warn"),
                            finding("extra.config", "skipped", [{"exists":False},{"exists":False}]))["diagnosis"]
        self.assertEqual([p['id'] for p in value['problems']], ['target.region'])
        self.assertIn("无需按此项改动", value["checks"][0]["text"])

    def test_socks_tls_bypass_and_provider_conflicts_have_specific_actions(self):
        cli = {"installation_count":1,"proxy_scheme":"socks5","proxy_bypass":{"target_matches":["claude.ai"]},
               "tls_verification_disabled":True,"bedrock":True,"vertex":True,"extra_ca_configured":True,"extra_ca_exists":False}
        value = report_with(finding("extra.cli_env", "warn", [cli]))["diagnosis"]
        self.assertTrue({"cli.socks","cli.bypass","cli.tls_disabled","cli.providers","cli.ca_missing"} <= {p["id"] for p in value["problems"]})
        self.assertEqual(next(p for p in value["problems"] if p["id"]=="cli.socks")["repair"], "cli-proxy")

    def test_desktop_scope_does_not_request_cli_repairs(self):
        bad = {"exists":True,"valid":False,"line":2,"column":3,"repairable":"trailing_comma"}
        value = report_with(finding("extra.config", "warn", [{"exists":False},bad]),
                            finding("extra.cli_env","warn",[{"installation_count":1,"proxy_scheme":"socks5"}]), preferences={"usage":"desktop"})["diagnosis"]
        self.assertFalse(any(p["id"].startswith(("cli.","config.cli")) for p in value["problems"]))

    def test_code_scope_does_not_require_desktop_guard_or_tun(self):
        value = report_with(finding("extra.cli_env", "pass", [{"installation_count":1}]),
                            finding("baseline.guard", "warn", [{"registered":False}]), finding("baseline.tun"),
                            preferences={"usage":"cli","require_guard":True,"require_rules":True})["diagnosis"]
        self.assertFalse(any(p["id"].startswith(("maintenance.","startup.")) for p in value["problems"]))

    def test_unsafe_account_and_low_disk_have_preserving_steps(self):
        value = report_with(finding("extra.account", "warn", [{"valid":True,"pending":[".new"]}]),
                            finding("extra.storage", "warn", [{"free_bytes":100}]))["diagnosis"]
        self.assertEqual({p["id"] for p in value["problems"]}, {"account.integrity","storage.low"})
        self.assertTrue(all(p["repair"] is None for p in value["problems"]))

    def test_missing_evidence_after_a_fix_is_unverified_not_resolved(self):
        before = report_with(finding("extra.proxy_listener", "warn", [{"tcp_accepts":False}]))["diagnosis"]
        missing = report_with(finding("extra.proxy_listener"))["diagnosis"]
        healthy = report_with(finding("extra.proxy_listener", "pass", [{"tcp_accepts":True}]))["diagnosis"]
        self.assertEqual(len(compare_diagnoses(before,missing)["unverified"]),1)
        self.assertFalse(compare_diagnoses(before,missing)["resolved"])
        self.assertEqual(len(compare_diagnoses(before,healthy)["resolved"]),1)

    def test_malformed_configuration_reports_line_and_a_real_repair(self):
        shape = {"exists":True,**inspect_text('{\n"x":1,\n}')}
        value = report_with(finding("extra.config", "warn", [shape,{"exists":False}]))["diagnosis"]
        self.assertEqual(value["problems"][0]["repair"],"json-desktop")
        self.assertRegex(value["problems"][0]["observed"],r"第 [23] 行、第 [1-6] 列")

    def test_exported_html_has_solutions_without_raw_json_or_detail_controls(self):
        r=report_with(finding("baseline.reachability","unknown",[response(0,"curl_exit_6")]))
        page=html_report(redact(r))
        self.assertIn("目标域名无法解析",page)
        self.assertNotIn("<details",page)
        self.assertNotIn('"endpoint"',page)
        self.assertIn("代理路径",page)

    def test_latency_points_to_a_measured_stage_and_ignores_metadata_service(self):
        value=report_with(finding('extra.timing','warn',[{'endpoint':'https://claude.ai/','total_ms':4000,'dns_ms':10,'tcp_ms':20,'tls_ms':30,'first_byte_ms':3900}]))['diagnosis']
        self.assertEqual(value['problems'][0]['id'],'performance.latency')
        self.assertIn('等待首字节',value['problems'][0]['observed'])
        value=report_with(finding('extra.timing','warn',[{'endpoint':'https://ipinfo.io/json','total_ms':4000}]))['diagnosis']
        self.assertFalse(value['problems'])

    def test_duplicate_entrypoints_are_reviewed_not_automatically_uninstalled(self):
        value=report_with(finding('extra.cli_env','warn',[{'installation_count':2}]))['diagnosis']
        p=value['problems'][0];self.assertEqual(p['id'],'cli.multiple_paths')
        self.assertIsNone(p['repair']);self.assertIn('/doctor',p['steps'][0])


class ConfigurationRepairFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.profile=self.home/'Claude';self.profile.mkdir()
        self.manager=ConfigRemedies(self.home,self.profile,environ={})


class ConfigurationRepairTests(ConfigurationRepairFixture):

    def test_lexical_fix_preserves_commas_brackets_and_escapes_inside_strings(self):
        original='{"mcpServers":{"local":{"args":["literal ,}","literal ,]","quote \\\"",],},},"secret":"SENSITIVE",}'
        fixed=remove_trailing_commas(original)
        value=json.loads(fixed)
        self.assertEqual(value["mcpServers"]["local"]["args"],['literal ,}','literal ,]','quote "'])
        self.assertEqual(value["secret"],"SENSITIVE")
        self.assertTrue(inspect_text(fixed)["valid"])

    def test_missing_commas_duplicates_and_nonstandard_numbers_are_not_guessed(self):
        for text in ('{"a":1 "b":2}', '{"a":1,"a":2,}', '{"a":NaN,}'):
            self.assertIsNone(remove_trailing_commas(text))
            self.assertFalse(inspect_text(text)["valid"])

    def test_confirmed_edit_backup_hash_and_undo_restore_exact_original(self):
        path=self.manager.paths['desktop'];original=b'\xef\xbb\xbf{"mcpServers":{},"token":"PRIVATE",}'
        path.write_bytes(original)
        change=self.manager.preview('desktop',{'trailing_comma'})
        self.assertEqual(path.read_bytes(),original)
        result=self.manager.apply([change])
        self.assertEqual(result['state'],'completed')
        token=result['backups'][0]['id']
        backup=self.manager.backups/(token+'.private.json')
        self.assertEqual(backup.read_bytes(),original)
        self.assertTrue(config_shape(path)['valid'])
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(self.manager.undo(token,False)['state'],'confirmation_required')
        self.assertTrue(config_shape(path)['valid'])
        self.assertEqual(self.manager.undo(token,True)['state'],'completed')
        self.assertEqual(path.read_bytes(),original)
        self.assertTrue(backup.exists())

    def test_file_change_after_preview_prevents_overwrite(self):
        path=self.manager.paths['desktop'];path.write_text('{"a":1,}',encoding='utf-8')
        change=self.manager.preview('desktop',{'trailing_comma'})
        path.write_text('{"a":2}',encoding='utf-8')
        with self.assertRaises(ValueError):self.manager.apply([change])
        self.assertEqual(json.loads(path.read_text(encoding='utf-8')),{'a':2})

    def test_undo_refuses_changes_made_after_repair(self):
        path=self.manager.paths['desktop'];path.write_text('{"a":1,}',encoding='utf-8')
        result=self.manager.apply([self.manager.preview('desktop',{'trailing_comma'})])
        path.write_text('{"new":"user-work"}',encoding='utf-8')
        with self.assertRaises(ValueError):self.manager.undo(result['backups'][0]['id'],True)
        self.assertEqual(json.loads(path.read_text(encoding='utf-8')),{'new':'user-work'})

    def test_proxy_and_tls_fix_preserve_secrets_and_unrelated_bypasses(self):
        path=self.manager.paths['cli'];path.parent.mkdir()
        path.write_text(json.dumps({'model':'example','env':{'API_KEY':'PRIVATE','NO_PROXY':'private.company claude.ai *.anthropic.com','NODE_TLS_REJECT_UNAUTHORIZED':'0'}}),encoding='utf-8')
        change=self.manager.preview('cli',{'proxy','tls'},'http://127.0.0.1:7897')
        self.manager.apply([change]);data=json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(data['env']['API_KEY'],'PRIVATE');self.assertEqual(data['model'],'example')
        self.assertEqual(data['env']['NO_PROXY'],'private.company')
        self.assertEqual(data['env']['no_proxy'],'private.company')
        self.assertEqual(data['env']['NODE_TLS_REJECT_UNAUTHORIZED'],'1')
        facts=cli_facts(self.home,{'PATH':'','HTTPS_PROXY':'socks5://127.0.0.1:7898'})
        self.assertEqual(facts['proxy_scheme'],'http')
        self.assertFalse(facts['tls_verification_disabled'])
        self.assertNotIn('PRIVATE',json.dumps(facts))

    def test_undo_new_configuration_removes_only_the_created_file(self):
        change=self.manager.preview('cli',{'tls'})
        result=self.manager.apply([change]);self.assertTrue(self.manager.paths['cli'].exists())
        self.manager.undo(result['backups'][0]['id'],True)
        self.assertFalse(self.manager.paths['cli'].exists())

    def test_unknown_targets_and_remote_or_credentialed_proxy_are_rejected(self):
        with self.assertRaises(ValueError):self.manager.preview('../outside',{'tls'})
        for url in ('http://example.com:80','http://user:pass@127.0.0.1:80','socks5://127.0.0.1:80'):
            with self.assertRaises(ValueError):self.manager.preview('cli',{'proxy'},url)

    def test_link_or_reparse_point_is_rejected_before_write(self):
        fake=Mock(st_mode=0o100644,st_file_attributes=0x400)
        with patch('envscope.remedies.Path.lstat',return_value=fake):
            with self.assertRaises(ValueError):self.manager.preview('cli',{'tls'})

    def test_second_configuration_manager_cannot_write_during_first_lock(self):
        other=ConfigRemedies(self.home,self.profile)
        with self.manager._lock():
            with self.assertRaises(ValueError):other.apply([])

    def test_partial_write_keeps_first_backup_and_does_not_claim_success(self):
        for path in self.manager.paths.values():
            path.parent.mkdir(exist_ok=True);path.write_text('{"a":1,}',encoding='utf-8')
        changes=[self.manager.preview(k,{'trailing_comma'}) for k in ('desktop','cli')]
        import envscope.remedies as module
        original=module._replace
        def replace(path,*args):
            if path==self.manager.paths['cli']:raise OSError('fixture')
            original(path,*args)
        with patch('envscope.remedies._replace',side_effect=replace):result=self.manager.apply(changes)
        self.assertEqual(result['state'],'partial');self.assertEqual(len(result['backups']),1)
        self.assertFalse(config_shape(self.manager.paths['cli'])['valid'])
        self.manager.undo(result['backups'][0]['id'],True)
        self.assertFalse(config_shape(self.manager.paths['desktop'])['valid'])


class PlanTests(ConfigurationRepairFixture):
    def plans(self, tester=None):
        legacy=Mock();legacy.capabilities.return_value={'actions':[]}
        return SolutionPlans(self.manager,legacy,lambda:[{'url':'http://127.0.0.1:7897'}],tester or Mock(return_value={'evidence':[response()]}))

    def bad_report(self):
        path=self.manager.paths['desktop'];path.write_text('{"a":1,}',encoding='utf-8')
        return report_with(finding('extra.config','warn',[config_shape(path),{'exists':False}]))

    def test_plan_needs_confirmation_is_single_use_and_contains_no_config_content(self):
        r=self.bad_report();plans=self.plans();plan=plans.prepare(r)
        self.assertEqual(plan['state'],'planned');self.assertNotIn('before',plan)
        self.assertEqual(plans.apply(plan['plan_id'],r,False)['state'],'confirmation_required')
        self.assertFalse(config_shape(self.manager.paths['desktop'])['valid'])
        self.assertEqual(plans.apply(plan['plan_id'],r,True)['state'],'executed')
        self.assertEqual(plans.apply(plan['plan_id'],r,True)['state'],'retest_required')

    def test_expired_changed_or_imported_reports_cannot_authorize_edits(self):
        for change in ('expired','changed','imported'):
            r=self.bad_report();plans=self.plans();plan=plans.prepare(r);other=deepcopy(r)
            if change=='expired':other['created_at']=(datetime.now(timezone.utc)-timedelta(seconds=100)).isoformat()
            if change=='changed':other['report_id']='different'
            if change=='imported':other['mode']='legacy-import'
            self.assertEqual(plans.apply(plan['plan_id'],other,True)['state'],'retest_required')
            self.assertFalse(config_shape(self.manager.paths['desktop'])['valid'])

    def test_http_proxy_is_tested_before_it_can_enter_a_plan(self):
        r=report_with(finding('extra.cli_env','warn',[{'installation_count':1,'proxy_scheme':'socks5'}]))
        failed=Mock(return_value={'evidence':[response(407)]});plans=self.plans(failed)
        self.assertEqual(plans.prepare(r)['state'],'guided');self.assertFalse(self.manager.paths['cli'].exists())
        success=Mock(return_value={'evidence':[response()]});plans=self.plans(success);plan=plans.prepare(r)
        self.assertEqual(plan['state'],'planned');success.assert_called_once_with('http://127.0.0.1:7897')
        self.assertFalse(self.manager.paths['cli'].exists())
        self.assertEqual(plans.apply(plan['plan_id'],r,True)['state'],'executed')

    def test_installer_opening_is_waiting_not_repaired(self):
        legacy=Mock();legacy.capabilities.return_value={'actions':[{'id':'fix','available':False},{'id':'install','available':True,'effects':['打开交互安装器']}]}
        legacy.run.return_value={'state':'started'}
        r=report_with(finding('extra.desktop','pass',[{'found':True}]),finding('baseline.tun','pass'),
                      finding('baseline.guard','warn',[{'registered':False}]),preferences={'require_guard':True})
        plans=SolutionPlans(self.manager,legacy,lambda:[],Mock())
        plan=plans.prepare(r);result=plans.apply(plan['plan_id'],r,True)
        self.assertEqual(result['state'],'waiting_install');self.assertFalse(result['needs_retest'])
        legacy.run.assert_called_once_with('install',{},confirmed=True)

    def test_failed_maintenance_after_config_edit_is_partial_with_undo(self):
        r=self.bad_report();r['diagnosis']['problems'].append({'id':'maintenance.rules','title':'rules','repair':'legacy'})
        legacy=Mock();legacy.capabilities.return_value={'actions':[{'id':'fix','available':True,'effects':['重写规则']}]}
        legacy.run.return_value={'state':'failed','reason':'fixture'}
        plans=SolutionPlans(self.manager,legacy,lambda:[],Mock())
        plan=plans.prepare(r);result=plans.apply(plan['plan_id'],r,True)
        self.assertEqual(result['state'],'partial');self.assertTrue(result['needs_retest'])
        self.assertEqual(len(result['backups']),1)
        self.manager.undo(result['backups'][0]['id'],True)
        self.assertFalse(config_shape(self.manager.paths['desktop'])['valid'])


class SolutionAPITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name);self.store=StateStore(memory=True)
        self.store.save_settings({'usage':'desktop','connection_mode':'http_proxy','usage_country':'US'}, confirm_environment=True)
        self.ops=Operations(self.store,self.home,discoverer=lambda:[],remedy_opener=Mock(return_value=True))
        self.file=self.ops.config_remedies.paths['desktop'];self.file.parent.mkdir(parents=True)
        self.original=b'{"mcpServers":{},"fixture":"PRIVATE_FIXTURE",}'
        self.file.write_bytes(self.original)
        def auditor(*args,**kwargs):
            return [finding('extra.config','warn',[config_shape(self.file),{'exists':False}]),finding('baseline.reachability','pass',[response()]),finding('baseline.country','pass',[{'actual':'US'}])]
        self.server=make_server(auditor=auditor,store=self.store,operations=self.ops)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.origin='http://127.0.0.1:'+str(self.server.server_port);self.opener=build_opener(ProxyHandler({}))
        self.token=json.loads(self.opener.open(self.origin+'/api/session').read())['token']

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()

    def post(self,path,body):
        request=Request(self.origin+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':self.origin,'X-EnvScope-Token':self.token})
        return json.loads(self.opener.open(request,timeout=3).read())

    def audit(self):
        from tests.test_desktop import snapshot
        self.current=self.post('/api/audit',{'snapshot':snapshot()})
        return self.current

    def action(self,name,params=None,confirmed=False):
        if name in ('solution-plan','solution-open'):
            params={'report_id':self.current['report_id'],**(params or {})}
        return self.post('/api/action',{'action':name,'params':params or {},'confirmed':confirmed})

    def test_actual_api_plan_apply_recheck_and_undo_preserve_private_fixture(self):
        before=self.audit();self.assertEqual(before['diagnosis']['problems'][0]['id'],'config.desktop')
        plan=self.action('solution-plan');self.assertEqual(self.file.read_bytes(),self.original)
        result=self.action('solution-apply',{'plan_id':plan['plan_id']},True)
        self.assertEqual(result['state'],'executed');self.assertNotIn('PRIVATE_FIXTURE',json.dumps(result))
        after=self.audit();self.assertEqual(len(after['resolution']['resolved']),1)
        self.assertFalse(after['resolution']['unverified']);self.assertTrue(config_shape(self.file)['valid'])
        self.assertEqual(self.action('solution-undo',{'backup_id':result['backups'][0]['id']},True)['state'],'completed')
        self.assertEqual(self.file.read_bytes(),self.original)
        restored=self.audit();self.assertEqual(restored['diagnosis']['problems'][0]['id'],'config.desktop')
        self.assertNotIn('PRIVATE_FIXTURE',json.dumps(restored))

    def test_file_open_uses_problem_allowlist_and_requires_backup_confirmation(self):
        self.audit()
        self.assertEqual(self.action('solution-open',{'problem_id':'config.desktop'})['state'],'confirmation_required')
        self.ops.remedy_opener.assert_not_called()
        self.assertEqual(self.action('solution-open',{'problem_id':'forged'})['state'],'retest_required')
        self.assertEqual(self.action('solution-open',{'problem_id':'config.desktop'},True)['state'],'opened')
        self.ops.remedy_opener.assert_called_once_with('config-desktop')

    def test_unconfirmed_apply_cannot_modify_files_or_discard_the_reviewed_report(self):
        self.audit();plan=self.action('solution-plan')
        value=self.action('solution-apply',{'plan_id':plan['plan_id']})
        self.assertEqual(value['state'],'confirmation_required')
        self.assertEqual(self.file.read_bytes(),self.original)
        self.assertEqual(self.action('solution-apply',{'plan_id':plan['plan_id']},True)['state'],'executed')

    def test_history_or_forged_report_id_cannot_plan_or_open_current_configuration(self):
        self.audit()
        self.assertEqual(self.action('solution-plan',{'report_id':'old-or-forged'})['state'],'retest_required')
        self.assertEqual(self.action('solution-open',{'problem_id':'config.desktop','report_id':'old-or-forged'},True)['state'],'retest_required')
        self.ops.remedy_opener.assert_not_called()
        self.assertEqual(self.file.read_bytes(),self.original)

    def test_one_stop_setup_api_reports_current_file_receipt_without_private_hashes(self):
        self.ops.config_remedies.environ={}
        self.ops.solutions.proxy_tester=Mock(return_value={'evidence':[response()]})
        self.store.save_settings({'usage':'cli'}, confirm_environment=True)
        cli_file=self.ops.config_remedies.paths['cli']
        def auditor(*args,**kwargs):
            return [finding('extra.cli_env','pass',[{'installation_count':1,'config':config_shape(cli_file)}]),
                    finding('extra.config','pass',[{'exists':False},config_shape(cli_file)]),
                    finding('baseline.reachability','pass',[response()])]
        self.server.auditor=auditor
        before=self.audit();self.assertTrue(any(p['id']=='target.cli_path' for p in before['diagnosis']['problems']))
        plan=self.action('solution-plan',{'enhance_cli':True})
        self.assertFalse(cli_file.exists())
        result=self.action('solution-apply',{'plan_id':plan['plan_id']},True)
        self.assertNotIn('before',result)
        after=self.audit()
        self.assertFalse(after['resolution']['resolved'])
        self.assertEqual(after['resolution']['configuration'][0]['state'],'verified')
        self.assertEqual(after['resolution']['configuration'][0]['scope'],'user-config-file-only')
        self.assertNotIn('after_hash',json.dumps(after))
        self.assertNotEqual(after['decision']['verdict'],'clear_in_scope')

    def test_setup_flags_cannot_be_nonboolean_or_supply_remote_proxy(self):
        from urllib.error import HTTPError
        self.audit()
        for params in ({'enhance_cli':'yes'},{'enhance_cli':True,'proxy':'http://proxy.example:8080'},
                       {'enhance_cli':True,'proxy':'http://user:PRIVATE@127.0.0.1:7897'}):
            with self.assertRaises(HTTPError) as caught:
                self.action('solution-plan',params)
            self.assertEqual(caught.exception.code,400)
        self.assertEqual(self.file.read_bytes(),self.original)


class ProxyHeaderTests(unittest.TestCase):
    def test_connect_407_is_kept_when_curl_returns_receive_error(self):
        def runner(command,**kwargs):
            Path(command[command.index('--dump-header')+1]).write_bytes(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nSet-Cookie: PRIVATE\r\n\r\n')
            return subprocess.CompletedProcess(command,56,stdout='')
        transport=CurlTransport(runner=runner);transport.executable='fixture'
        result=transport.get('https://api.anthropic.com')
        self.assertEqual(result.status,407)
        self.assertEqual(application_state(result),'proxy_authentication_required')
        self.assertNotIn('PRIVATE',str(result))
        diagnosis=report_with(finding('baseline.reachability','warn',[{'endpoint':'https://api.anthropic.com','http_status':result.status,'error':result.error}]))['diagnosis']
        self.assertEqual(len(diagnosis['problems']),1)
        self.assertIn('代理服务器要求认证',diagnosis['problems'][0]['title'])

    def test_retry_after_is_selected_and_invalid_values_are_not_exposed(self):
        for value,expected in (('45',45),('-4',None),('PRIVATE_VALUE',None)):
            def runner(command,**kwargs):
                Path(command[command.index('--dump-header')+1]).write_text('HTTP/1.1 429 Too Many Requests\nRetry-After: '+value+'\n\n',encoding='ascii')
                return subprocess.CompletedProcess(command,0,stdout='{}'+MARKER+'429|application/json|0.01|0.02|0.04|0.08|0.1|0|2')
            transport=CurlTransport(runner=runner);transport.executable='fixture'
            result=transport.get('https://api.anthropic.com')
            self.assertEqual(result.retry_after_seconds,expected)
            self.assertNotIn('PRIVATE_VALUE',str(result))


class FixedSystemEntryTests(unittest.TestCase):
    def test_windows_setting_entry_is_a_fixed_argv_without_a_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            ops=Operations(StateStore(memory=True),directory,discoverer=lambda:[])
            with patch('envscope.operations.platform.system',return_value='Windows'),patch('envscope.operations.subprocess.Popen') as runner:
                self.assertTrue(ops._open_remedy('clock-settings'))
                args=runner.call_args.args[0]
                self.assertEqual(args[-1],'ms-settings:dateandtime')
                self.assertNotIn('shell',runner.call_args.kwargs)
                self.assertFalse(ops._open_remedy('arbitrary'))
                self.assertEqual(runner.call_count,1)

    def test_mac_config_entry_creates_a_real_backup_before_injected_editor(self):
        with tempfile.TemporaryDirectory() as directory:
            ops=Operations(StateStore(memory=True),directory,discoverer=lambda:[])
            path=ops.config_remedies.paths['cli'];path.parent.mkdir(parents=True)
            original=b'{"fixture":"PRIVATE",';path.write_bytes(original)
            with patch('envscope.operations.platform.system',return_value='Darwin'),patch('envscope.operations.subprocess.Popen') as runner:
                self.assertTrue(ops._open_remedy('config-cli'))
                self.assertEqual(runner.call_args.args[0],['/usr/bin/open','-e',str(path)])
                backups=list(ops.config_remedies.backups.glob('*.private.json'))
                self.assertEqual(len(backups),1);self.assertEqual(backups[0].read_bytes(),original)
                self.assertEqual(path.read_bytes(),original)
