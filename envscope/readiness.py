"""Explain desktop handoff conditions without granting an authorization token.

The action handler always repeats native measurements. A ready checklist is
only a summary of the listed observations, never an account or privacy verdict.
"""
from datetime import datetime, timezone


def launch_readiness(report, preferences=None):
    preferences = preferences or {}
    checks = []

    def add(key, title, ready, reason):
        checks.append({"id": key, "title": title, "state": "ready" if ready else "attention", "reason": reason})

    report = report if isinstance(report, dict) else {}
    fresh = False
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(report["created_at"])).total_seconds()
        fresh = report.get("mode") == "one-click-desktop" and 0 <= age < 90
    except (KeyError, ValueError, TypeError, OverflowError):
        pass
    add("fresh", "本机最新检测", fresh, "操作前仍会重新检测。" if fresh else "先完成本机检测；历史或过期报告不能用于启动。")
    if report.get('environment') or preferences.get('environment_confirmed'):
        from .target_environment import fingerprint
        from .assessment import assessment
        matching = preferences.get('environment_confirmed') and report.get('environment', {}).get('fingerprint') == fingerprint(preferences)
        add('target', '目标环境一致', matching, '按已确认目标复检。' if matching else '目标已变化，请先确认目标并复检。')
        desktop_used = preferences.get('usage') in ('desktop', 'both')
        add('usage', '桌面使用范围', desktop_used, '已选择桌面用途。' if desktop_used else '当前目标未选择桌面用途；打开桌面或切换账号前请调整目标并复检。')
        for item in assessment(report, preferences)['items']:
            if item['required']:
                title = next((f['title'] for f in report.get('findings', []) if f['id'] == item['id']), item['id'])
                add(item['id'], title, item['state'] == 'passed', item['reason'])
        reasons = [c['reason'] for c in checks if c['state'] != 'ready']
        return {'ready': not reasons, 'checks': checks, 'reasons': reasons,
                'scope': '按明确选择的目标检查启动条件；标准连接不提供严格 TUN 保护。真实登录、回复及隐私覆盖仍需分别验证。'}
    findings = report.get("findings", [])
    findings = [f for f in findings if isinstance(f, dict)] if isinstance(findings, list) else []
    by_id = {f.get("id"): f for f in findings if isinstance(f.get("id"), str)}

    def first(key):
        values = by_id.get(key, {}).get("evidence")
        return values[0] if isinstance(values, list) and values and isinstance(values[0], dict) else {}

    installed = first("extra.desktop").get("found") is True
    add("installation", "Claude 桌面安装", installed, "已在所检查位置找到。" if installed else "未确认桌面安装，请先安装官方 Claude 桌面版。")
    config = first("extra.config")
    config_ready = config.get("exists") is False or config.get("exists") is True and config.get("valid") is True
    add("configuration", "桌面配置", config_ready,
        "所检查的配置格式可读，或尚未创建可选文件。" if config_ready else "桌面配置未确认可读；先处理格式或访问问题，再复检。")
    account = first("extra.account")
    account_ready = (account.get("valid") is True and isinstance(account.get("pending"), list) and not account["pending"]
                     and (account.get("tracked") is False or account.get("tracked") is True and account.get("live_profile_present") is True))
    add("accounts", "账号资料状态", account_ready,
        "所检查的标记与事务状态未见冲突。" if account_ready else "账号资料未确认完整，或仍有待恢复的副本。保留现有资料，先在账号页核对。")
    targets = by_id.get("baseline.reachability", {}).get("evidence", [])
    web = next((v for v in targets if isinstance(v, dict) and v.get("endpoint") == "https://claude.ai/"
                and v.get("tls_verified") is True and not v.get("error") and type(v.get("http_status")) is int
                and (200 <= v["http_status"] < 400 or v["http_status"] in (401, 403))), None) if isinstance(targets, list) else None
    add("service", "Claude 网页连接", web is not None,
        ("已收到可信连接的回应，仍需在 Claude 中确认登录或访问校验。" if web["http_status"] in (401, 403) else "所列网页端点已回应；还需在 Claude 中确认实际回复。") if web is not None
        else "尚未确认 Claude 网页端点连接；先处理对应连接问题，API 回应不能替代桌面访问。")
    required = ["http.egress", "udp.stun", "baseline.proxy", "baseline.tun", "baseline.ipv6"]
    if preferences.get("require_guard", True):
        required.append("baseline.guard")
    if preferences.get("require_rules", True):
        required.append("baseline.rules")
    titles = {"http.egress": "网络出口", "udp.stun": "实时连接出口", "baseline.proxy": "代理客户端",
              "baseline.tun": "全局连接接管", "baseline.ipv6": "IPv6 配置", "baseline.guard": "进程保护", "baseline.rules": "目标连接规则"}
    for key in required:
        finding = by_id.get(key, {})
        ready = finding.get("status") == "pass"
        add(key, titles[key], ready, "本轮在所列范围已核实。" if ready else titles[key] + "尚未通过，查看对应检测的原因与处理办法。")
    failed = [f.get("title", "未命名项目") for f in findings if f.get("status") == "fail"]
    add("failures", "已知失败项", not failed, "未发现标记为失败的项目。" if not failed else "先处理失败项：" + "、".join(str(v) for v in failed))
    reasons = [c["reason"] for c in checks if c["state"] != "ready"]
    return {"ready": not reasons, "checks": checks, "reasons": reasons,
            "scope": "启动条件仅覆盖所列观测，操作前复检；不证明账号权限、会话有效或没有网络泄漏。"}
