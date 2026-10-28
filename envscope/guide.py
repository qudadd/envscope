"""Plain-language tasks derived from measured evidence, never a login verdict."""
from urllib.parse import urlsplit


LESSON_VERSION = 1
USAGES = ("auto", "desktop", "cli", "both")

# These explanations accompany, rather than replace, the pinned 14-item protocol.
EXPLANATIONS = {
    "proxy": ("连接工具有没有工作", "代理", "把请求交给你已有的连接工具。工具没启动或端口失效时，Claude 可能连不上。", "先打开平时使用的连接工具，再测试连接；只用隧道模式时不一定需要本地代理端口。"),
    "tun": ("需要的应用能否走同一条连接", "TUN / 虚拟网卡", "一种接管应用网络请求的方式。普通网页或 Code 能连接时，不必为了这一项单独开启；严格账号切换有额外要求。", "只有准备使用严格账号切换、或确实需要隧道接管时，再核对客户端的 TUN 和服务权限。"),
    "country": ("连接显示的地区是否符合你的设置", "出口国家", "记录本次网络出口的地区。它不能证明账号有使用资格，也不要求你修改真实所在地。", "没有设置比较目标时无需处理。填错目标时修正设置；服务是否支持实际地区请核对官方说明。"),
    "ip_stability": ("连接地址最近有没有变化", "出口变化", "频繁重连可能伴随地址变化；变化本身不能说明账号有风险。第一次检测没有历史可比较。", "经常中断时查看历史和持续维护记录，结合客户端重连情况排查。"),
    "timezone": ("电脑时间是否影响登录", "时区与系统时钟", "明显的时钟偏差可能导致证书或登录失败。时区名称不同本身不是故障。", "有时钟偏差时先启用系统自动校时；没有比较目标时不必改时区。"),
    "locale": ("地区格式有没有意外改变", "地区格式", "主要记录日期和数字的地区格式。使用中文格式不自动影响 Claude 连接。", "按自己的实际习惯保留设置；只有明确设置了目标且发生变化时才核对。"),
    "ipv6": ("另一种网络地址是否也按预期连接", "IPv6", "电脑可能同时使用两种地址。只验证其中一种，不能说明另一种也走了相同路径。", "只有出现明确的路径差异或违反自己设置的允许范围时再处理；无响应不证明已经关闭。"),
    "dns": ("电脑能不能找到 Claude 的服务器", "DNS / 域名解析", "先把网站名字转换为连接地址。解析失败会影响连接；本工具还不能证明所有解析请求的真实出口。", "发现解析失败或本地覆盖时再处理。显示实际 DNS 出口未核实，表示检测能力有限，不等于发现泄漏。"),
    "webrtc": ("浏览器是否使用了另一条网络路径", "UDP / WebRTC", "浏览器的实时连接可能与网页请求走不同路径；本页观测与系统探测分别记录。", "按实际使用的浏览器复检；未取得地址时保持未核实，不为得到通过而盲目修改系统。"),
    "guard": ("连接异常时有没有进程保护", "进程守护", "claude-switcher 的保护任务可在条件异常时停止客户端，可能中断未保存工作；它和定时检查是两项功能。", "需要这项保护时先预览安装影响。仅想记录变化，可启用 EnvScope 的定时复检。"),
    "rules": ("Claude 请求有没有匹配预期连接规则", "路由规则", "兼容的开源连接内核可报告正在生效的规则。只在文件中写过规则，不代表它已经生效。", "规则可读时按实际结果修复；接口不兼容时保留未核实，不能改称已经通过。"),
    "language": ("应用语言是否符合你的习惯", "客户端语言", "记录 Claude 自己的语言偏好。没有读取到偏好不代表不能使用，也不要求改成英语。", "没有实际语言问题时无需改动；可在 Claude 中自行确认。"),
    "asn": ("这条连接由哪家网络提供", "ASN / 网络归属", "用于排障时识别网络提供方。机构名称无法证明连接质量、住宅属性或账号风险。", "这是资料项，无需仅为这个名称更换服务或删除账号资料。"),
    "reachability": ("Claude 服务器有没有回应", "服务连接", "分别联系网页和 API，不发送密钥。API 返回未认证可以说明收到回应，不能证明登录或模型权限。", "先处理具体的连接错误；收到回应后，还需要在自己的 Claude 中发一条消息。"),
}


def explain_check(key, status, has_problem):
    label, term, why, next_step = EXPLANATIONS[key]
    result = ("有相关问题，按上方建议处理" if has_problem else
              "按实际需要设置" if status == "not_configured" else
              "资料项，无需因此改动" if status == "info" or key == "asn" else
              "本次所列范围已核实" if status == "pass" else
              "本次没有测量" if status == "skipped" else
              "还有内容需要核对" if status in ("warn", "fail") else "本次还不能确认")
    return {"label": label, "term": term, "why": why, "next_step": next_step, "result": result}


def usage_guide(report):
    """No successful anonymous probe is promoted to an authenticated result."""
    findings = {f["id"]: f for f in report.get("findings", [])}
    problems = report.get("diagnosis", {}).get("problems", [])
    def first(key):
        return next((v for v in findings.get(key, {}).get("evidence", []) if isinstance(v, dict)), {})
    usage = report.get("usage", "auto")
    cli = first("extra.cli_env")
    desktop = first("extra.desktop")
    selected = ["desktop", "cli"] if usage == "both" else [usage] if usage != "auto" else (
        (["desktop"] if desktop.get("found") is True else []) + (["cli"] if type(cli.get("installation_count")) is int and cli["installation_count"] > 0 else []))
    setup_problems = [p for p in problems if p["id"].startswith(("config.", "config_access.", "cli.", "desktop.", "clock.", "storage.", "account."))]
    network_problems = [p for p in problems if p["id"].startswith(("service.", "network.", "proxy.", "hosts.", "policy."))]
    protection_problems = [p for p in problems if p["id"].startswith(("maintenance.", "startup.", "target."))]
    installation_known = bool(selected) and all(desktop.get("found") is True if v == "desktop" else
        type(cli.get("installation_count")) is int and cli["installation_count"] > 0 for v in selected)
    config = findings.get("extra.config", {}).get("evidence", [])
    config_known = bool(selected) and all(len(config) > (0 if v == "desktop" else 1) and
        isinstance(config[0 if v == "desktop" else 1], dict) and
        (config[0 if v == "desktop" else 1].get("valid") is True or config[0 if v == "desktop" else 1].get("exists") is False) for v in selected)
    responses = findings.get("baseline.reachability", {}).get("evidence", [])
    def responds(host):
        for v in responses:
            if not isinstance(v, dict):
                continue
            try:
                actual = urlsplit(v.get("endpoint", "")).hostname
            except (ValueError, TypeError):
                continue
            code = v.get("http_status")
            if actual == host and v.get("tls_verified") is True and not v.get("error") and type(code) is int and (200 <= code < 400 or host == "api.anthropic.com" and code == 401):
                return True
        return False
    web, api = responds("claude.ai"), responds("api.anthropic.com")
    # Desktop and web need their own response; API success alone is insufficient.
    network_usage = "both" if len(selected) == 2 else selected[0] if selected else usage
    network_known = (api if network_usage == "cli" else web and api if network_usage == "both" else web if network_usage == "desktop" else api or web)
    custom_service = "cli" in selected and any(cli.get(key) for key in ("custom_endpoint", "bedrock", "vertex", "foundry"))
    if custom_service:
        network_known = False
    tasks = [
        {"id": "setup", "title": "软件和设置", "state": "attention" if setup_problems else "checked" if installation_known and config_known else "unverified",
         "text": "先修正下面列出的安装或配置问题。" if setup_problems else "已在所列位置找到软件，所选配置格式未发现问题；仍需在实际会话中确认生效。" if installation_known and config_known else "还没有完整确认所选软件和配置；未创建可选配置文件不算故障。", "problem_ids": [p["id"] for p in setup_problems]},
        {"id": "connection", "title": "连接 Claude", "state": "attention" if network_problems else "responding" if network_known else "unverified",
         "text": "本次公共端点探测没有验证你的自定义接口或云平台；请在实际会话中确认。" if custom_service else "按下方提示先解决连接问题。" if network_problems else "所选服务已回应；还没有验证登录和模型权限。" if network_known else "所选服务的回应还不完整。可先测试已有连接，再到实际客户端确认。", "problem_ids": [p["id"] for p in network_problems]},
        {"id": "protection", "title": "日常保持", "state": "attention" if protection_problems else "optional",
         "text": "有保护或启动条件需要核对；不把这些条件直接当成连接故障。" if protection_problems else "连接正常后可选择定时复检；是否已启用以持续维护页的系统任务状态为准。", "problem_ids": [p["id"] for p in protection_problems]},
    ]
    primary = problems[0] if problems else None
    if primary:
        headline, summary = "先处理这件事：" + primary["title"], "已按处理顺序列出原因和操作。执行修复前会预览具体改动，完成后重新检测。"
    elif network_known:
        headline, summary = "连接有回应，下一步试用 Claude", "现在到你平时使用的 Claude 登录并发一条消息，再决定是否启用持续维护。"
    else:
        headline, summary = "先确认能否连接 Claude", "本次证据还不足。先测试已有连接，或按实际遇到的现象获取处理步骤。"
    return {"schema_version": 1, "headline": headline, "summary": summary, "tasks": tasks,
            "primary_problem_id": primary["id"] if primary else None,
            "next_action": "repair" if primary and primary.get("repair") else "problem" if primary else "try" if network_known else "proxy-test",
            "manual_confirmation": {"state": "required", "text": "需要你在自己的 Claude 中确认登录并收到回复。本工具不会发送消息、读取密钥或代替账号验证。"},
            "boundary": "这些步骤用于定位使用问题；不证明全流量接管、零泄漏、地区资格或账号权限。"}
