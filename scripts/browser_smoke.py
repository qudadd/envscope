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

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"


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
                {"desktop_config":config_shape(config_file),"cli":{"config":{"exists":False}}}, {}))
    directory = tempfile.TemporaryDirectory()
    store = StateStore(memory=True)
    class FixtureOperations(Operations):
        def run(self, action, params, **kwargs):
            if action == "proxy-diagnose":
                return {"state": "completed", "evidence": [{"http_status": 403, "access": "access_denied"}], "boundary": "offline fixture"}
            return super().run(action, params, **kwargs)
    def never_run(*args, **kwargs):
        raise AssertionError("Smoke test must never execute the original backend")
    operations = FixtureOperations(store, directory.name, legacy=LegacyBridge(home=directory.name, runner=never_run),
                                   discoverer=lambda: [{"url": "http://127.0.0.1:7897", "sources": ["离线夹具"], "connection_verified": False}])
    config_file=operations.config_remedies.paths['desktop']
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
                config_file.write_bytes(original)
                context = browser.new_context(viewport={"width": width, "height": height}, accept_downloads=True,
                                              locale="zh-CN", timezone_id="UTC")
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                # Keep smoke tests entirely offline, including native browser STUN.
                page.add_init_script("window.RTCPeerConnection = undefined;")
                page.route("https://**/*", lambda route: route.abort())
                page.goto(f"http://127.0.0.1:{server.server_port}", wait_until="networkidle")
                page.screenshot(path=str(ARTIFACTS / f"{label}-initial.png"), full_page=True)
                page.get_by_role("button", name="一键检测").click()
                expect(page.locator("#share")).to_be_enabled()
                expect(page.locator("#verdict")).to_contain_text("1 个需要处理的问题")
                assert page.locator('#checks tr[data-check^="baseline."]').count()==14
                assert page.locator('#checks tr[data-check^="extra."]').count()==18
                expect(page.locator('#problems')).to_contain_text('配置结尾存在多余逗号')
                assert '查看详情' not in page.locator('#audit-results').inner_text()
                assert 'PRIVATE_FIXTURE' not in page.locator('body').inner_text()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "horizontal overflow"
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="导出结果").click()
                download = downloaded.value
                file = ARTIFACTS / f"{label}-share.json"
                download.save_as(str(file))
                value = json.loads(file.read_text(encoding='utf-8'))
                assert value["contains_sensitive"] is False
                assert value["mode"] == "one-click-desktop"
                assert 'PRIVATE_FIXTURE' not in json.dumps(value)
                page.screenshot(path=str(ARTIFACTS/f'{label}-diagnosis.png'))
                page.get_by_role('button',name='一站式处理',exact=True).click()
                expect(page.locator('#solution-plan')).to_contain_text('本次处理方案')
                assert config_file.read_bytes()==original, 'preview must not edit'
                page.screenshot(path=str(ARTIFACTS/f'{label}-plan.png'))
                page.get_by_role('button',name='确认执行此方案',exact=True).click()
                expect(page.locator('#resolution')).to_contain_text('1 项已确认消除')
                expect(page.locator('#verdict')).to_have_text('Claude 服务已返回响应')
                assert config_shape(config_file)['valid']
                page.screenshot(path=str(ARTIFACTS/f'{label}-resolved.png'))
                page.get_by_role('button',name='撤销 Claude 桌面配置',exact=True).click()
                expect(page.locator('#verdict')).to_contain_text('1 个需要处理的问题')
                assert config_file.read_bytes()==original
                page.get_by_role('button',name='一站式处理',exact=True).click()
                expect(page.locator('#solution-plan')).to_contain_text('本次处理方案')
                page.get_by_role('button',name='确认执行此方案',exact=True).click()
                expect(page.locator('#resolution')).to_contain_text('1 项已确认消除')
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
                page.get_by_role("button", name="重新检测", exact=True).click()
                expect(page.locator("#share")).to_be_enabled()
                page.get_by_role("button", name="历史", exact=True).click()
                page.get_by_role("button", name="比较", exact=True).click()
                expect(page.locator("#history-output")).to_contain_text("出口证据不足")
                page.screenshot(path=str(ARTIFACTS / f"{label}-history.png"), full_page=True)
                for name in ("检测", "账号", "工具", "历史", "设置"):
                    page.get_by_role("button", name=name, exact=True).click()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), name + " overflow"
                assert not errors, errors
                summary[label] = {"page_errors": 0, "horizontal_overflow": False,
                                  "baseline_categories": 14, "extended_checks": 18, "one_stop_repair": "passed", "recheck":"passed", "undo":"passed", "no_raw_details":True, "share_download": "passed", "account_labels": "passed",
                                  "proxy_diagnostics": "passed", "preferences": "passed", "history_compare": "passed"}
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
