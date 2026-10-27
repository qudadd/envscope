import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .browser import load_snapshot
from .controller import validate_controller
from .model import make_report
from .policy import Policy
from .probes import audit
from .report import STATUSES, VERDICTS, diff_reports, html_report, read_report, redact, write_json
from .switcher import import_text
from .transport import CurlTransport, validate_url
from .service import make_server
from .state import StateStore


def parser():
    root = argparse.ArgumentParser(description="EnvScope：一键桌面环境工具；audit 子命令为只读诊断。")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("audit", help="采集和评估；默认离线，网络探测须 --online")
    run.add_argument("--online", action="store_true", help="向已列出的公共端点发出无认证 HTTP 探测")
    run.add_argument("--stun", action="store_true", help="另向 Cloudflare/Google 发出原生 UDP STUN；不是浏览器探测")
    run.add_argument("--ipv6", action="store_true", help="另测 IPv6 出口；无响应记为未知")
    run.add_argument("--proxy", help="显式 curl 代理；不会失败后直连重试，凭据建议通过 --proxy-env 提供")
    run.add_argument("--proxy-env", help="从指定环境变量读取代理 URL")
    run.add_argument("--target", action="append", default=[], help="附加无认证 HTTP GET 目标，最多 8 个")
    run.add_argument("--browser", help="5 分钟内导出的浏览器原始观测 JSON")
    run.add_argument("--controller", help="只读 Clash 兼容接口，例如 http://127.0.0.1:9090")
    run.add_argument("--controller-secret-env", default="ENVSCOPE_CONTROLLER_SECRET")
    run.add_argument("--policy", help="私有 JSON 策略文件，勿提交真实地址")
    run.add_argument("--profile", choices=("privacy", "transport"), default="privacy")
    for command in (run,):
        command.add_argument("--output", default="reports/audit.json")
        command.add_argument("--html", help="另存无外部资源的 HTML 报告")
        command.add_argument("--include-sensitive", action="store_true", help="在本地报告保留原始地址，不适合直接公开")
    sub.add_parser("desktop", help="自动打开本地一键检测窗口")
    serve = sub.add_parser("serve", help="在 loopback 提供一键检测页；数据仅传到本机进程")
    serve.add_argument("--port", type=int, default=8765)
    imported = sub.add_parser("import-switcher", help="只解析已保存的 checkdetail 文本，不执行上游脚本")
    imported.add_argument("input")
    imported.add_argument("--output", default="reports/switcher-import.json")
    render = sub.add_parser("report", help="将已保存的 EnvScope 报告转换为 HTML")
    render.add_argument("input")
    render.add_argument("--html", required=True)
    comparison = sub.add_parser("diff", help="比较两份报告的检查状态；不使用脱敏别名比较 IP")
    comparison.add_argument("before")
    comparison.add_argument("after")
    return root


def save(report, output, html_path=None, sensitive=False):
    report["contains_sensitive"] = sensitive
    public = report if sensitive else redact(report)
    write_json(public, output)
    if html_path:
        path = Path(html_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_report(public), encoding="utf-8")
    # Never print evidence, proxy URLs, or addresses by default.
    print("EnvScope " + __version__ + " · " + VERDICTS[public["decision"]["verdict"]])
    for finding in public["findings"]:
        print("  " + finding["id"] + " [" + STATUSES[finding["status"]] + "] " + finding["summary"])
    print("JSON: " + str(Path(output).resolve()))
    return 0 if report["decision"]["verdict"] == "clear_in_scope" else 1 if report["decision"]["verdict"] == "blocked" else 2


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "desktop":
            from .desktop import main as desktop_main
            return desktop_main()
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            server = make_server(args.port)
            print("浏览器自检页：http://127.0.0.1:" + str(args.port) + "；按 Ctrl+C 停止。", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        if args.command == "diff":
            print(json.dumps(diff_reports(read_report(args.before), read_report(args.after)), ensure_ascii=False, indent=2))
            return 0
        if args.command == "report":
            path = Path(args.html)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html_report(redact(read_report(args.input))), encoding="utf-8")
            print(str(path.resolve()))
            return 0
        if args.command == "import-switcher":
            file = Path(args.input)
            if file.stat().st_size > 1048576:
                raise ValueError("input too large")
            findings = import_text(file.read_text(encoding="utf-8-sig"))
            return save(make_report(findings, Policy(), "legacy-import"), args.output)
        if (args.stun or args.ipv6 or args.target or args.controller) and not args.online:
            raise ValueError("network options require --online")
        if len(args.target) > 8:
            raise ValueError("at most 8 targets are allowed")
        for url in args.target:
            validate_url(url)
        if args.controller:
            validate_controller(args.controller)
        if args.proxy and args.proxy_env:
            raise ValueError("use only one proxy input")
        proxy = args.proxy
        if args.proxy_env:
            proxy = os.environ.get(args.proxy_env)
            if not proxy:
                raise ValueError("proxy environment variable is empty; refusing alternate path")
        transport = CurlTransport(proxy)
        policy = Policy.load(args.policy, args.profile)
        snapshot = load_snapshot(args.browser) if args.browser else None
        findings = audit(policy, transport, args.online, args.stun, args.ipv6, args.target, snapshot,
                         args.controller, os.environ.get(args.controller_secret_env), baseline_config=StateStore().settings())
        return save(make_report(findings, policy), args.output, args.html, args.include_sensitive)
    except (ValueError, OSError) as exc:
        # Parser/OS exception details can contain credentials or private file content.
        print("EnvScope 输入或本地资源错误（" + type(exc).__name__ + "）；请检查参数、文件格式和权限。", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
