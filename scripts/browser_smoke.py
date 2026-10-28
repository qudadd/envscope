"""Offline UI smoke test. Playwright is a development tool, not a dependency."""
import json
from pathlib import Path
import threading
import tempfile

from playwright.sync_api import expect, sync_playwright
from envscope.service import make_server
from envscope.model import Finding, Status
from envscope.baseline import DOMAINS
from envscope.extended import extended_checks
from envscope.operations import Operations
from envscope.state import StateStore
from envscope.legacy import LegacyBridge
from envscope.local_facts import config_shape
from envscope.maintenance import Maintenance

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"


class OfflineScheduler:
    """A fake OS registrar: browser smoke tests never install a real job."""
    def __init__(self):
        self.spec = None

    def build(self, interval):
        return {"system": "offline-fixture", "body": "offline", "interval": interval}

    def inspect(self, spec=None):
        registered = bool(self.spec and self.spec == spec)
        return {"present": self.spec is not None, "owned": registered, "registered": registered, "state": "registered" if registered else "missing"}

    def install(self, spec, previous=None):
        self.spec = spec

    def remove(self, spec):
        self.spec = None


def main():
    ARTIFACTS.mkdir(exist_ok=True)
    def fixture_audit(*args, **kwargs):
        findings = [Finding("system.inventory", "系统信息", Status.PASS, "离线测试夹具", "test-fixture"),
                Finding("dns.leak", "DNS", Status.UNKNOWN, "没有权威侧观测", "test-fixture"),
                Finding("browser.webrtc", "WebRTC", Status.UNKNOWN, "浏览器功能不可用", "test-fixture")]
        names = [("proxy", "代理客户端"), ("tun", "TUN 网卡"), ("country", "出口国家"), ("ip_stability", "出口变化"),
                 ("timezone", "时区"), ("locale", "地区格式"), ("ipv6", "IPv6 配置"), ("dns", "DNS 配置"),
                 ("webrtc", "UDP / WebRTC"), ("guard", "守护进程"), ("rules", "代理路由规则"), ("language", "客户端语言"), ("asn", "ASN 信息"), ("reachability", "服务连接")]
        baseline = [Finding("baseline." + key, title, Status.UNKNOWN, "离线夹具：尚无有效证据", "test-fixture") for key, title in names]
        baseline[-1] = Finding("baseline.reachability", "服务连接", Status.PASS, "离线响应夹具", "test-fixture",
                               [{"endpoint":"https://api.anthropic.com/v1/models","http_status":401,"error":"","tls_verified":True}])
        return (findings + baseline + extended_checks({}, {"dns": [], "routes": []},
                {"desktop_config":config_shape(config_file),"cli":{"config":config_shape(cli_file)}}, {}))
    directory = tempfile.TemporaryDirectory()
    store = StateStore(memory=True)
    class FixtureOperations(Operations):
        def run(self, action, params, **kwargs):
            if action == "proxy-diagnose":
                return {"state": "completed", "evidence": [{"http_status": 403, "access": "access_denied"}], "boundary": "offline fixture"}
            return super().run(action, params, **kwargs)
    def never_run(*args, **kwargs):
        raise AssertionError("Smoke test must never execute the original backend")
    operations = FixtureOperations(store, directory.name, legacy=LegacyBridge(platform_name='Windows', home=directory.name, runner=never_run),
                                   discoverer=lambda: [{"url": "http://127.0.0.1:7897", "sources": ["离线夹具"], "connection_verified": False}])
    config_file=operations.config_remedies.paths['desktop']
    cli_file=operations.config_remedies.paths['cli']
    cli_file.parent.mkdir(parents=True,exist_ok=True)
    operations.maintenance=Maintenance(store, remedies=operations.config_remedies, scheduler=OfflineScheduler(),
                                       auditor=fixture_audit, proxy_tester=lambda proxy: True, home=directory.name)
    config_file.parent.mkdir(parents=True,exist_ok=True)
    original=b'{"mcpServers":{},"fixture":"PRIVATE_FIXTURE",}'
    server = make_server(auditor=fixture_audit, store=store, operations=operations)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    summary = {}
    try:
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            for label, width, height in (("desktop-small", 1024, 800), ("desktop", 1280, 1000), ("desktop-wide", 1440, 1000)):
                store._learning = {"version": 0, "completed": False}
                store.save_settings({"usage": "auto", "country": ""})
                config_file.write_bytes(original)
                cli_file.write_text(json.dumps({"env":{"HTTPS_PROXY":"http://127.0.0.1:7897","https_proxy":"http://127.0.0.1:7897",
                                                       "NODE_TLS_REJECT_UNAUTHORIZED":"1"}}),encoding='utf-8')
                context = browser.new_context(viewport={"width": width, "height": height}, accept_downloads=True,
                                              locale="zh-CN", timezone_id="UTC")
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                # Keep smoke tests entirely offline, including native browser STUN.
                page.add_init_script("window.RTCPeerConnection = undefined;")
                page.route("https://**/*", lambda route: route.abort())
                page.goto(f"http://127.0.0.1:{server.server_port}", wait_until="networkidle")
                expect(page.locator('#learning-panel')).to_be_visible()
                expect(page.locator('#audit-content')).to_be_hidden()
                expect(page.locator('#learning-title')).to_have_text('你准备怎样使用 Claude？')
                before_learning_settings=store.settings()
                page.screenshot(path=str(ARTIFACTS / f"{label}-initial.png"), full_page=True)
                page.get_by_role('radio',name='Claude Code 在终端或编辑器里写代码、运行任务。',exact=True).check()
                page.locator('#learning-next').click()
                expect(page.locator('#learning-title')).to_contain_text('只用先看下一步')
                page.locator('#learning-back').click()
                expect(page.locator('input[name="lesson-usage"][value="cli"]')).to_be_checked()
                page.locator('input[name="lesson-usage"][value="auto"]').check()
                page.locator('#learning-next').click()
                page.screenshot(path=str(ARTIFACTS / f"{label}-lesson.png"), full_page=True)
                page.locator('#learning-next').click()
                expect(page.locator('#learning-title')).to_contain_text('再选择怎样保持')
                assert store.settings()==before_learning_settings, 'reading the lesson must not save network preferences'
                assert not operations.maintenance._config().get('enabled'), 'reading must not install a job'
                page.get_by_role('button',name='开始第一次检测',exact=True).click()
                expect(page.locator("#share")).to_be_enabled()
                expect(page.locator("#verdict")).to_contain_text("先处理这件事")
                assert store.learning()['completed'] is True
                assert not page.locator('#technical-details').evaluate('(node)=>node.open')
                assert not page.locator('#beginner-checks').evaluate('(node)=>node.open')
                expect(page.locator('#usage-tasks')).to_contain_text('软件和设置')
                assert page.locator('#checks tr[data-check^="baseline."]').count()==14
                assert page.locator('#checks tr[data-check^="extra."]').count()==18
                assert page.locator('#claude-check-rows [data-claude-check]').count()==14
                expect(page.locator('#problems')).to_contain_text('配置结尾存在多余逗号')
                assert '查看详情' not in page.locator('#audit-results').inner_text()
                assert 'PRIVATE_FIXTURE' not in page.locator('body').inner_text()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "horizontal overflow"
                page.locator('#technical-details>summary').click()
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="导出结果").click()
                download = downloaded.value
                file = ARTIFACTS / f"{label}-share.json"
                download.save_as(str(file))
                value = json.loads(file.read_text(encoding='utf-8'))
                assert value["contains_sensitive"] is False
                assert value["mode"] == "one-click-desktop"
                assert 'PRIVATE_FIXTURE' not in json.dumps(value)
                page.evaluate('window.scrollTo(0,0)')
                page.locator('#technical-details>summary').click()
                page.evaluate('window.scrollTo(0,0)')
                page.screenshot(path=str(ARTIFACTS/f'{label}-diagnosis.png'))
                page.locator('#beginner-checks>summary').click()
                page.locator('[data-claude-check="dns"]>summary').click()
                expect(page.locator('[data-claude-check="dns"]')).to_contain_text('电脑能不能找到 Claude 的服务器')
                expect(page.locator('[data-claude-check="dns"]')).to_contain_text('能力有限，不等于发现泄漏')
                expect(page.locator('[data-claude-check="dns"]')).to_contain_text('怎样长期保持')
                page.locator('#claude-checklist').screenshot(path=str(ARTIFACTS/f'{label}-checklist.png'))
                page.locator('#beginner-checks>summary').click()
                page.get_by_role('button',name='预览可修复内容',exact=True).click()
                expect(page.locator('#solution-plan')).to_contain_text('本次处理方案')
                assert config_file.read_bytes()==original, 'preview must not edit'
                page.screenshot(path=str(ARTIFACTS/f'{label}-plan.png'))
                page.get_by_role('button',name='确认执行此方案',exact=True).click()
                expect(page.locator('#resolution')).to_contain_text('1 项已确认消除')
                expect(page.locator('#verdict')).to_have_text('连接有回应，下一步试用 Claude')
                assert config_shape(config_file)['valid']
                page.screenshot(path=str(ARTIFACTS/f'{label}-resolved.png'))
                page.get_by_role('button',name='撤销 Claude 桌面配置',exact=True).click()
                expect(page.locator('#verdict')).to_contain_text('先处理这件事')
                assert config_file.read_bytes()==original
                page.get_by_role('button',name='预览可修复内容',exact=True).click()
                expect(page.locator('#solution-plan')).to_contain_text('本次处理方案')
                page.get_by_role('button',name='确认执行此方案',exact=True).click()
                expect(page.locator('#resolution')).to_contain_text('1 项已确认消除')
                # A fresh page has no in-memory undo buttons. Its per-item plan
                # must still be visible, and persistent backups must be listed.
                page.reload(wait_until='networkidle')
                expect(page.locator('#learning-panel')).to_be_hidden()
                page.get_by_role('button',name='使用教学',exact=True).click()
                expect(page.locator('#learning-panel')).to_be_visible()
                page.get_by_role('button',name='稍后学习',exact=True).click()
                expect(page.locator('#learning-panel')).to_be_hidden()
                page.get_by_role('button',name='一键检测',exact=True).click()
                expect(page.locator('#share')).to_be_enabled()
                page.locator('#try-success').click()
                expect(page.locator('#try-feedback')).to_contain_text('不会改变技术检测结论')
                page.locator('#try-help').click()
                page.locator('#symptom').select_option('code')
                expect(page.locator('#symptom-advice')).to_contain_text('claude doctor')
                page.locator('#symptom').select_option('mcp')
                expect(page.locator('#symptom-advice')).to_contain_text('/mcp')
                page.screenshot(path=str(ARTIFACTS/f'{label}-symptoms.png'))
                page.locator('#symptom-help>summary').click()
                expect(page.locator('#solution-tools')).to_be_hidden()
                page.locator('#beginner-checks>summary').click()
                page.locator('[data-claude-check="guard"]>summary').click()
                page.locator('[data-claude-check="guard"]').get_by_role('button',name='审核本项处理方案',exact=True).click()
                expect(page.locator('#solution-tools')).to_be_visible()
                expect(page.locator('#solution-plan')).to_contain_text('本次处理方案')
                page.get_by_role('button',name='工具',exact=True).click()
                expect(page.locator('#config-backups')).to_contain_text('Claude 桌面配置')
                assert 'PRIVATE_FIXTURE' not in page.locator('#config-backups').inner_text()
                page.get_by_role('button',name='持续维护',exact=True).click()
                expect(page.locator('#upkeep-state')).to_contain_text('尚未启用')
                page.locator('#upkeep-restore').check()
                page.locator('#upkeep-prepare').click()
                expect(page.locator('#upkeep-plan')).to_contain_text('确认启用持续维护')
                assert not operations.maintenance._config().get('enabled'), 'preview must not enable a job'
                page.get_by_role('button',name='确认启用持续维护',exact=True).click()
                expect(page.locator('#upkeep-state')).to_contain_text('等待首次巡检')
                drift=json.loads(cli_file.read_text(encoding='utf-8'))
                drift['env']['HTTPS_PROXY']='http://127.0.0.1:9999'
                drift['env']['OTHER']='preserve unrelated new setting'
                cli_file.write_text(json.dumps(drift),encoding='utf-8')
                page.locator('#upkeep-run').click()
                expect(page.locator('#upkeep-state')).to_contain_text('巡检已完成')
                expect(page.locator('#upkeep-events')).to_contain_text('已备份并恢复')
                restored=json.loads(cli_file.read_text(encoding='utf-8'))
                assert restored['env']['HTTPS_PROXY']=='http://127.0.0.1:7897'
                assert restored['env']['OTHER']=='preserve unrelated new setting'
                page.screenshot(path=str(ARTIFACTS/f'{label}-upkeep.png'),full_page=True)
                page.locator('#upkeep-report').click()
                expect(page.locator('#session-state')).to_contain_text('后台原生巡检')
                assert page.locator('#claude-check-rows [data-claude-check]').count()==14
                expect(page.locator('#try-feedback')).to_have_text('尚未由你确认实际回复。')
                page.get_by_role('button',name='持续维护',exact=True).click()
                page.get_by_role('button',name='停用并撤销 Claude Code 用户配置',exact=True).first.click()
                expect(page.locator('#upkeep-state')).to_contain_text('尚未启用')
                expect(page.locator('#upkeep-output')).to_contain_text('已恢复原配置')
                assert json.loads(cli_file.read_text(encoding='utf-8'))['env']['HTTPS_PROXY'].endswith(':9999')
                page.get_by_role("button", name="账号", exact=True).click()
                expect(page.locator("#account-list")).to_contain_text("A")
                assert page.locator("#account-list tr").count() >= 5
                page.locator("#new-slot").fill("work")
                page.locator("#new-label").fill("工作账号")
                page.get_by_role("button", name="添加", exact=True).click()
                expect(page.locator("#account-list")).to_contain_text("工作账号")
                expect(page.locator("#account-output")).to_contain_text("账号名称已保存")
                page.screenshot(path=str(ARTIFACTS / f"{label}-accounts.png"), full_page=True)
                page.get_by_role("button", name="工具", exact=True).click()
                expect(page.locator('#opensource-options')).to_contain_text('Mihomo')
                expect(page.locator('#opensource-options')).to_contain_text('Clash Verge Rev')
                page.locator("#proxy-url").fill("http://127.0.0.1:7897")
                page.get_by_role("button", name="测试连接", exact=True).click()
                expect(page.locator("#tool-output")).to_contain_text("自动探测被拒绝")
                page.locator("#maintenance-action").select_option("snapshot-export")
                expect(page.locator("#maintenance-run")).to_be_disabled()
                page.screenshot(path=str(ARTIFACTS / f"{label}-tools.png"), full_page=True)
                page.get_by_role("button", name="设置", exact=True).click()
                page.locator("input[name=country]").fill("US")
                page.get_by_role("button", name="保存", exact=True).click()
                expect(page.locator("#settings-output")).to_contain_text("已保存")
                page.screenshot(path=str(ARTIFACTS / f"{label}-settings.png"), full_page=True)
                page.get_by_role("button", name="检测", exact=True).click()
                page.locator('#start').click()
                expect(page.locator("#share")).to_be_enabled()
                page.get_by_role("button", name="历史", exact=True).click()
                page.get_by_role("button", name="比较", exact=True).click()
                expect(page.locator("#history-output")).to_contain_text("出口证据不足")
                page.screenshot(path=str(ARTIFACTS / f"{label}-history.png"), full_page=True)
                for name in ("检测", "持续维护", "账号", "工具", "历史", "设置"):
                    page.get_by_role("button", name=name, exact=True).click()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), name + " overflow"
                page.get_by_role('button',name='检测',exact=True).click()
                page.route('**/api/audit',lambda route:route.fulfill(status=503,content_type='application/json',body='{"error":"offline fixture failure"}'))
                page.locator('#start').click()
                expect(page.locator('#start')).to_be_enabled()
                expect(page.locator('#verdict')).to_contain_text('系统检测没有完成')
                expect(page.locator('#usage-tasks')).to_contain_text('尚无本轮系统结论')
                expect(page.locator('#try-claude')).to_be_hidden()
                expect(page.locator('#beginner-checks')).to_be_hidden()
                page.unroute('**/api/audit')
                assert not errors, errors
                summary[label] = {"page_errors": 0, "horizontal_overflow": False,
                                  "baseline_categories": 14, "extended_checks": 18, "one_stop_repair": "passed", "recheck":"passed", "undo":"passed", "no_raw_details":True, "share_download": "passed", "account_labels": "passed",
                                  "proxy_diagnostics": "passed", "preferences": "passed", "history_compare": "passed",
                                  "source_mapped_checklist":14,"maintenance_preview_enable":"passed","config_drift_restore":"passed",
                                  "unrelated_settings_preserved":"passed","maintenance_stop_and_undo":"passed",
                                  "per_item_plan_visible_without_problems":"passed","persistent_backup_list":"passed",
                                  "first_launch_teaching":"passed","teaching_back_and_replay":"passed","teaching_persistence":"passed",
                                  "plain_check_explanations":14,"symptom_help":"passed","manual_trial_separate_and_reset":"passed",
                                  "advanced_records_collapsed":"passed","open_source_roles":"passed","failed_audit_clears_old_guidance":"passed"}
                context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        directory.cleanup()
    (ARTIFACTS / "browser-smoke.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
