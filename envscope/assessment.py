"""Explain coverage and usability without changing the strict privacy policy."""


def denied(value):
    if isinstance(value, dict):
        return value.get("error") == "permission_denied" or any(denied(v) for v in value.values())
    return isinstance(value, list) and any(denied(v) for v in value)


def assessment(report, preferences=None):
    preferences = preferences or {}
    if report.get('environment', {}).get('confirmed'):
        return target_assessment(report)
    findings = report.get("findings", [])
    by_id = {f["id"]: f for f in findings}
    usage = report.get("usage", "auto")
    cli = next((v for v in by_id.get("extra.cli_env", {}).get("evidence", []) if isinstance(v, dict)), {})
    cli_used = usage in ("cli", "both") or usage == "auto" and bool(cli.get("installation_count") or cli.get("config", {}).get("exists"))
    desktop_used = usage in ("desktop", "both") or usage == "auto" and not cli_used
    required = {"extra.dns_resolution", "extra.tls", "baseline.reachability", "extra.config", "extra.storage"}
    if cli_used:
        required.update(("extra.cli_env", "extra.cli_paths"))
    if desktop_used:
        required.update(("extra.desktop", "extra.profile", "extra.account"))
    required.add("http.egress")
    # The separate privacy decision and account-launch gate retain their strict
    # required checks. This view assesses only the listed basic-use conditions.
    details = []
    for f in findings:
        key, status = f["id"], f["status"]
        state = {"pass": "passed", "warn": "review", "fail": "problem", "skipped": "not_applicable"}.get(status, "unavailable")
        reason, next_step, action = f["summary"], f.get("suggestion", ""), None
        if status in ("unknown", "skipped") and denied(f.get("evidence", [])):
            state, reason = "permission", "系统明确拒绝了读取权限。"
            next_step, action = "只为此项开放读取权限，完成授权后重新检测。", "permission-help"
        elif key in ("network.route", "dns.leak"):
            state = "unsupported"
            reason = "尚未实现进程与网络流量关联。" if key == "network.route" else "尚未接入权威 DNS 出口收集服务。"
            next_step = "本版不能验证这项能力，授予更多权限也不会补全；此项不算通过。"
        elif key in ("extra.cli_env", "extra.cli_paths") and not cli_used and status != "fail":
            state, reason, next_step = "not_applicable", "当前选择桌面使用，未要求使用 Claude Code。", "以后使用 Code 时，在使用范围中选择 Code 后重新检测。"
        elif key in ("extra.cli_env", "extra.config") and status == "skipped":
            state, reason, next_step = "not_applicable", "检查已完成，没有需要核对的可选自定义配置。", "无需创建空配置；登录状态仍在实际 Claude 中确认。"
        elif key == "extra.cli_paths" and status == "skipped" and cli_used:
            state, reason, next_step = "problem", "所选使用范围需要 Claude Code，但 PATH 中没有找到入口。", "安装 Claude Code 或修正 PATH，再重新打开 EnvScope 检测。"
        elif key in ("extra.desktop", "extra.profile") and not desktop_used:
            state, reason, next_step = "not_applicable", "当前使用范围不需要 Claude 桌面资料。", "使用桌面版时重新选择使用范围。"
        elif key in ("extra.desktop", "extra.profile") and status == "unknown" and any(v.get("found", v.get("exists")) is False for v in f.get("evidence", []) if isinstance(v, dict)):
            state, next_step = "problem", "安装并打开官方 Claude 桌面版，完成首次登录后重新检测。"
        elif key in ("baseline.country", "baseline.timezone", "baseline.locale", "baseline.language") and not preferences.get({"baseline.country": "country", "baseline.timezone": "timezone", "baseline.locale": "locale", "baseline.language": "locale"}[key]):
            state, reason, next_step = "informational", "已保留可读取的资料；没有设置需要比较的目标。", "这项不要求修改系统。只有明确需要比较时，才在设置中填写目标。"
        elif key in ("http.ipv6", "browser.http_v6", "udp.stun", "browser.webrtc") and status == "unknown":
            state, reason = "probe_incomplete", f["summary"]
            next_step = "本次探测没有取得完整响应；检查当前网络和客户端协议支持后重测。没有响应不等于无泄漏，也不能靠文件权限修复。"
        elif status == "unknown":
            next_step = next_step or "检查此项证据中的错误后重新检测；没有明确的权限拒绝时，无需提升应用权限。"
        if key == "extra.cli_env" and cli_used and (cli.get("tls_verification_disabled") is True or cli.get("endpoint_valid") is False or cli.get("proxy_valid") is False or cli.get("api_key_present") and cli.get("auth_token_present")):
            state, next_step = "problem", "在首页审核已生成的 Code 修复方案；修改后自动复检，并重新打开 Code。"
        if key == "extra.config" and any(isinstance(v, dict) and v.get("valid") is False for v in f.get("evidence", [])):
            state, next_step = "problem", "在首页查看具体配置错误；先备份，再按位置修复并重新检测。"
        details.append({"id": key, "state": state, "reason": reason, "next_step": next_step,
                        "action": action, "required": key in required, "measured_status": status})
    missing = required - by_id.keys()
    for key in sorted(missing):
        details.append({"id": key, "state": "unavailable", "reason": "本轮没有返回必需项目的结果。", "next_step": "重新完成检测。", "action": None, "required": True, "measured_status": "unknown"})
    blockers = [d for d in details if d["state"] == "problem"]
    pending = [d for d in details if d["required"] and d["state"] not in ("passed", "not_applicable", "informational")]
    verdict = "needs_fix" if blockers else "incomplete" if pending else "qualified_in_scope"
    counts = {state: sum(d["state"] == state for d in details) for state in ("passed", "problem", "review", "permission", "probe_incomplete", "unavailable", "unsupported", "not_applicable", "informational")}
    return {"verdict": verdict, "headline": {"needs_fix": "环境有不合格项，先处理下面的问题", "incomplete": "环境尚未验收：关键检查需要补全", "qualified_in_scope": "本次已检查的使用条件合格"}[verdict],
            "summary": f"通过 {counts['passed']} 项，发现问题 {counts['problem']} 项，需复核 {counts['review']} 项；关键待处理 {len(pending)} 项。",
            "counts": counts, "items": details,
            "boundary": "结论仅覆盖列出的使用条件；真实登录、订阅权限及回复仍需在 Claude 中确认。进程接管和权威 DNS 出口未验证，不代表完整隐私合格。"}


def target_assessment(report):
    env = report['environment']
    required, excluded = set(env['required']), env['excluded']
    details = []
    for f in report.get('findings', []):
        key, status = f['id'], f['status']
        state = {'pass': 'passed', 'fail': 'problem', 'warn': 'review', 'skipped': 'unavailable'}.get(status, 'unavailable')
        reason, step, action = f['summary'], f.get('suggestion', ''), None
        if denied(f.get('evidence', [])):
            state, action = 'permission', 'permission-help'
            step = '系统明确拒绝读取；只为本项开放所需权限后复检。'
        elif key == 'extra.cli_paths' and status == 'skipped':
            state, reason = 'problem', '所选用途需要 Code，但 PATH 中未找到入口。'
        elif key == 'extra.cli_env' and status == 'skipped':
            state, reason = 'passed', '已检查所列环境变量，没有可选自定义配置；登录另行确认。'
        elif key in ('extra.desktop', 'extra.profile') and any(v.get('found', v.get('exists')) is False for v in f.get('evidence', []) if isinstance(v, dict)):
            state = 'problem'
        elif key == 'extra.cli_env' and status == 'warn':
            state = 'problem'
        if key in excluded:
            state, reason = 'not_applicable', excluded[key]
        elif key in ('network.route', 'dns.leak'):
            state = 'unsupported'
            reason = '本版没有相应测量能力，保留为未验证；不作为所选基础使用目标的验收项。'
        elif key not in required and state != 'permission':
            state = 'informational'
            reason = '参考记录，不作为本次目标的验收条件。' + reason
        details.append({'id': key, 'state': state, 'reason': reason, 'next_step': step,
                        'action': action, 'required': key in required, 'measured_status': status})
    for key in sorted(required - {f['id'] for f in report.get('findings', [])}):
        details.append({'id': key, 'state': 'unavailable', 'reason': '本轮未返回该目标必需的证据。',
                        'next_step': '重新检测；缺少证据不能判为通过。', 'action': None, 'required': True, 'measured_status': 'unknown'})
    active = [d for d in details if d['required']]
    pending = [d for d in active if d['state'] != 'passed']
    blockers = [d for d in active if d['state'] == 'problem']
    verdict = 'needs_fix' if blockers else 'incomplete' if pending else 'qualified_in_scope'
    states = ('passed', 'problem', 'review', 'permission', 'probe_incomplete', 'unavailable', 'unsupported', 'not_applicable', 'informational')
    counts = {s: sum(d['state'] == s for d in details) for s in states}
    return {'verdict': verdict, 'headline': {'needs_fix': '目标环境有不合格项', 'incomplete': '目标环境仍有待完成的检查', 'qualified_in_scope': '所选目标的环境检查合格'}[verdict],
            'summary': f"必需检查 {len(active)} 项：通过 {len(active)-len(pending)} 项，不合格 {len(blockers)} 项，待完成 {len(pending)-len(blockers)} 项。",
            'counts': counts, 'items': details, 'target_summary': env['summary'],
            'boundary': '合格仅指所选目标与已测条件；请在实际 Claude 中完成登录并确认回复。参考项保留原始结果，完整隐私保护、进程接管和权威 DNS 出口不据此判为通过。'}
