"""Fourteen baseline categories, keeping observed signals separate from claims."""
from concurrent.futures import ThreadPoolExecutor
import json
import ipaddress
import os
import platform
import re
import shutil
import subprocess
from urllib.request import build_opener, ProxyHandler, Request

from .model import Finding, Status
from .policy import normalize_ip
from .transport import response_evidence
from .discovery import config_documents

DOMAINS = ("claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com", "challenges.cloudflare.com",
           "datadoghq.com", "segment.io", "stripe.com", "stripe.network", "stripecdn.com",
           "intercom.io", "intercomcdn.com", "intercomassets.com")


def baseline_finding(name, title, status, summary, evidence=(), limitations=()):
    return Finding("baseline." + name, title, status, summary, "baseline-observation", list(evidence), list(limitations))


def proxy_runtime(inventory, preferences):
    network = inventory.get("network", {})
    clients = network.get("known_clients", [])
    if isinstance(clients, str):
        clients = [clients]
    expected = preferences.get("client", "auto")
    names = {"clash-verge": ("mihomo", "verge-mihomo"), "sing-box": ("sing-box",), "shadowrocket": ("shadowrocket",),
             "clashx": ("clashx",), "surge": ("surge",)}
    matches = clients if expected == "auto" else [c for c in clients if str(c).lower() in names.get(expected, ())]
    return baseline_finding("proxy", "代理客户端", Status.PASS if matches else Status.UNKNOWN,
                            "已发现所选代理客户端进程" if matches else "未确认所选代理客户端进程", [{"clients": clients}],
                            ["进程存在不等于流量已接管。"])


def tunnel(inventory):
    adapters = inventory.get("network", {}).get("adapters", [])
    candidates = []
    for adapter in adapters if isinstance(adapters, list) else []:
        description = str(adapter.get("InterfaceDescription", adapter.get("name", "")))
        up = adapter.get("Status") == "Up" or "UP" in adapter.get("flags", [])
        if up and re.search(r"TUN|TAP|Wintun|WireGuard|VPN|Tailscale|utun", description, re.I):
            candidates.append({"name": adapter.get("Name", adapter.get("name")), "active": True})
    return baseline_finding("tun", "TUN 网卡", Status.PASS if candidates else Status.UNKNOWN,
                            "发现启用的隧道网卡" if candidates else "未确认启用的隧道网卡", candidates,
                            ["这是网卡状态，目标流量关联另行显示。"])


def guard_state():
    try:
        if platform.system() == "Windows":
            script = "$t=Get-ScheduledTask -TaskName 'ClaudeBodyguard' -ErrorAction SilentlyContinue; if($t){@{registered=$true;enabled=([string]$t.State -ne 'Disabled');running=([string]$t.State -eq 'Running')}|ConvertTo-Json -Compress}else{'{\"registered\":false}'}"
            command = [shutil.which("powershell.exe") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
        elif platform.system() == "Darwin":
            command = ["/bin/launchctl", "print", "system/local.claude-bodyguard"]
        else:
            return {"registered": False, "error": "unsupported"}
        r = subprocess.run(command, capture_output=True, text=True, timeout=4,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if platform.system() == "Windows":
            if r.returncode != 0:
                raise ValueError("guard query unavailable")
            value = json.loads(r.stdout)
            if not isinstance(value, dict):
                raise ValueError("invalid guard response")
            return {"registered": value.get("registered") is True, "enabled": value.get("enabled") is True,
                    "running": value.get("running") is True, "kind": "scheduled-task"}
        return {"registered": r.returncode == 0 and bool(r.stdout.strip()), "enabled": r.returncode == 0,
                "running": bool(re.search(r"\bstate\s*=\s*running\b", r.stdout)), "kind": "launchd"}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"registered": False, "error": "unavailable"}


def verify_rules(config, rules, proxies, preferences):
    """Check the live rule order, destinations and selected node, never just counts."""
    if not isinstance(config, dict) or not isinstance(rules, dict) or not isinstance(proxies, dict):
        return {"status": "unknown", "reason": "运行配置格式无法识别"}
    mode = str(config.get("mode", "")).lower()
    if mode == "direct":
        return {"status": "fail", "reason": "代理内核处于直连模式", "mode": mode}
    entries = rules.get("rules")
    if mode not in ("global", "rule") or not isinstance(entries, list):
        return {"status": "unknown", "reason": "无法识别运行规则"}
    group = preferences.get("proxy_group", "")
    if mode == "global":
        group = "GLOBAL"
    elif not group:
        groups = {r["proxy"] for r in entries[:16] if isinstance(r, dict) and isinstance(r.get("proxy"), str) and r.get("payload") in DOMAINS}
        if len(groups) == 1:
            group = groups.pop()
    nodes, selected, seen = proxies.get("proxies"), group, set()
    if not group or not isinstance(nodes, dict):
        return {"status": "unknown", "reason": "未能确认目标代理组"}
    while True:
        node = nodes.get(selected)
        if selected in seen or not isinstance(node, dict):
            return {"status": "warn", "reason": "代理组选择无效或出现循环引用"}
        seen.add(selected)
        if "all" not in node and "now" not in node:
            break
        selected = node.get("now")
        if not isinstance(selected, str):
            return {"status": "warn", "reason": "代理组没有当前节点"}
    if str(node.get("type", "")).lower() in ("direct", "reject", "rejectdrop", "block", "pass"):
        return {"status": "fail", "reason": "当前代理组选择了直连或拒绝节点"}
    if not isinstance(node.get("type"), str) or not node["type"]:
        return {"status": "unknown", "reason": "当前节点类型无法识别"}
    policy = preferences.get("webrtc_policy", "proxy")
    if (mode == "global" or policy == "proxy") and node.get("udp") is not True:
        return {"status": "warn", "reason": "当前节点未确认支持 UDP"}
    if mode == "global":
        return {"status": "pass", "reason": "全局模式与当前代理节点已核对", "mode": mode,
                "scope": "runtime-configuration-only"}
    expected = [("port", p) for p in (3478, 5349, 19302)] + [("domain", d) for d in DOMAINS]
    if len(entries) < len(expected):
        return {"status": "warn", "reason": "运行规则数量不足"}
    for index, (kind, value) in enumerate(expected):
        rule = entries[index]
        if not isinstance(rule, dict):
            return {"status": "unknown", "reason": "运行规则格式无法识别"}
        rule_type = re.sub(r"[-_]", "", str(rule.get("type", "")).upper())
        payload = re.sub(r"[\s()_-]+", "", str(rule.get("payload", "")).upper()).replace("&&", ",")
        disabled = rule.get("disabled") is True or isinstance(rule.get("extra"), dict) and rule["extra"].get("disabled") is True
        target = "REJECT" if kind == "port" and policy == "reject" else group
        matches = ((rule_type == "AND" and payload == "NETWORK,UDP,DSTPORT," + str(value)) or
                   (rule_type == "DSTPORT" and payload == str(value))) if kind == "port" else rule_type == "DOMAINSUFFIX" and str(rule.get("payload", "")).strip().lower() == value
        if disabled or not matches or rule.get("proxy") != target:
            return {"status": "warn", "reason": "规则顺序、目标或启用状态不符合预期", "first_mismatch": str(value),
                    "expected_rule": {"position": index + 1, "kind": kind, "value": value, "target": target},
                    "actual_rule": {"type": rule_type, "payload": str(rule.get("payload", ""))[:200],
                                    "target": str(rule.get("proxy", ""))[:100], "disabled": disabled}}
    return {"status": "pass", "reason": "已核对 13 个域名、3 个 STUN 端口及当前节点", "mode": mode,
            "webrtc_policy": policy, "scope": "runtime-configuration-only"}


def runtime_rules(preferences):
    from .controller import NoRedirects, validate_controller
    origin, secret = "http://127.0.0.1:9090", os.environ.get("ENVSCOPE_CONTROLLER_SECRET", "")
    for content in config_documents():
        found = re.search(r"^external-controller:\s*[\"']?([^\s\"']+)", content, re.M)
        if found:
            candidate = found[1].replace("0.0.0.0:", "127.0.0.1:")
            try:
                origin = validate_controller("http://" + candidate)
            except ValueError:
                continue
        key = re.search(r"^secret:\s*[\"']?([^\s\"']*)", content, re.M)
        if key and key[1]:
            secret = key[1]
    try:
        headers = {"Accept": "application/json"}
        if secret:
            if len(secret) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in secret):
                raise ValueError("invalid controller secret")
            headers["Authorization"] = "Bearer " + secret
        opener = build_opener(ProxyHandler({}), NoRedirects())
        def read(endpoint):
            with opener.open(Request(origin + endpoint, headers=headers), timeout=2) as response:
                body = response.read(1048577)
            if len(body) > 1048576:
                raise ValueError("oversized runtime response")
            return json.loads(body)
        config = read("/configs")
        value = verify_rules(config, read("/rules"), read("/proxies"), preferences)
        tun = config.get("tun") if isinstance(config, dict) else None
        value["runtime"] = {"mode": config.get("mode"), "tun_enabled": tun.get("enable"), "auto_route": tun.get("auto-route"),
                            "dns_hijack_configured": bool(tun.get("dns-hijack"))} if isinstance(tun, dict) else {"mode": config.get("mode") if isinstance(config, dict) else None}
        return value
    except (OSError, ValueError, AttributeError):
        return {"status": "unknown", "reason": "无法读取或验证代理内核运行规则"}


def extra_network(transport):
    def metadata():
        response = transport.get("https://ipinfo.io/json")
        try:
            value = json.loads(response.body) if response.status == 200 and not response.error else {}
            if not isinstance(value, dict):
                return {}
            return {**{k: str(value[k])[:160] for k in ("country", "timezone", "org") if k in value},
                    "_transport": response_evidence("https://ipinfo.io/json", response)}
        except (ValueError, TypeError):
            return {}
    def target(url):
        response = transport.get(url, headers_only=url == "https://claude.ai/")
        return response_evidence(url, response)
    with ThreadPoolExecutor(max_workers=3) as pool:
        info = pool.submit(metadata)
        web = pool.submit(target, "https://claude.ai/")
        api = pool.submit(target, "https://api.anthropic.com/v1/models")
        return info.result(), [web.result(), api.result()]


def collect_baseline(inventory, v4, v6, udp_result, browser_result, preferences, transport, online=False, context=None):
    with ThreadPoolExecutor(max_workers=3) as pool:
        guard_job = pool.submit(guard_state)
        rules_job = pool.submit(runtime_rules, preferences) if online else None
        extra_job = pool.submit(extra_network, transport) if online else None
        guard = guard_job.result()
        rules = rules_job.result() if rules_job else {"status": "unknown", "reason": "尚未读取运行规则"}
        metadata, targets = extra_job.result() if extra_job else ({}, [])
    if context is not None:
        context.update(runtime=rules.get("runtime", {}), responses=targets + ([metadata["_transport"]] if "_transport" in metadata else []))
    expected_country = preferences.get("country")
    country = metadata.get("country") or next((o.get("country") for o in v4 if o.get("country")), None)
    timezone = inventory.get("network", {}).get("timezone_id") or inventory.get("timezone_iana")
    locale = inventory.get("locale")
    def setting(name, title, actual, expected):
        equal = str(actual).replace("_", "-").lower() == str(expected).replace("_", "-").lower()
        state = Status.PASS if expected and equal else Status.WARN if not expected else Status.UNKNOWN if not actual else Status.FAIL
        return baseline_finding(name, title, state, "符合设置的目标" if state == Status.PASS else "未设置比较目标，仅展示当前信息" if not expected else "当前信息与目标不同" if actual else "未取得当前信息",
                                [{"actual": actual, "expected": expected}], ["地区和语言差异不代表账号风险。"])
    network = inventory.get("network", {})
    bindings = network.get("ipv6_bindings", [])
    services = network.get("ipv6_services", [])
    disabled = (bool(bindings) and all(b.get("Enabled") is False for b in bindings)
                or bool(services) and all(s.get("ipv6_off") is True for s in services))
    valid_v6 = [o for o in v6 if o.get("ip") and ":" in o["ip"]]
    allowed = [ipaddress.ip_network(n) for n in preferences.get("allowed_ipv6", [])]
    policy_matches = bool(valid_v6 and allowed) and all(any(normalize_ip(o["ip"]) in n for n in allowed) for o in valid_v6)
    ipv6_status = Status.PASS if disabled or policy_matches else Status.UNKNOWN if not valid_v6 else Status.WARN
    language = inventory.get("client_language", {})
    language_result = (setting("language", "客户端语言", language.get("value"), preferences.get("language") if preferences.get('environment_confirmed') else preferences.get("locale"))
                       if language.get("source") == "application-preference" else baseline_finding("language", "客户端语言", Status.UNKNOWN,
                       "未取得客户端专用语言设置", [{"system_ui_language": language.get("value")}], ["系统语言不能代替 Claude 的实际语言偏好。分享时可不包含此项。 "]))
    rtc_states = {udp_result.status, browser_result.status}
    rtc_status = (Status.FAIL if Status.FAIL in rtc_states else Status.UNKNOWN if rtc_states & {Status.UNKNOWN, Status.SKIPPED}
                  else Status.WARN if Status.WARN in rtc_states else Status.PASS)
    findings = [proxy_runtime(inventory, preferences), tunnel(inventory), setting("country", "出口国家", country, expected_country),
                baseline_finding("ip_stability", "出口变化", Status.UNKNOWN, "在历史记录中比较检测前后的出口集合", limitations=["历史使用私有 HMAC，不公开原始地址。"]),
                setting("timezone", "时区", timezone, preferences.get("timezone")),
                setting("locale", "地区格式", locale, preferences.get("locale")),
                baseline_finding("ipv6", "IPv6 配置", ipv6_status, "系统报告已关闭已检查接口的 IPv6" if disabled else "有效观测符合指定 IPv6 范围" if policy_matches else "IPv6 是否符合预期需结合实际出口复核", [{"checked_interfaces_disabled": disabled}], ["IPv6 启用本身不构成泄漏；无响应也不是已关闭证明。"]),
                baseline_finding("dns", "DNS 配置", Status.PASS if network.get("dns") else Status.UNKNOWN,
                                 "已读取系统 DNS 配置" if network.get("dns") else "未取得 DNS 配置", [{"configured": bool(network.get("dns"))}], ["实际 DNS 出口由独立检查判断，配置存在不证明无泄漏。"]),
                baseline_finding("webrtc", "UDP / WebRTC", rtc_status, "系统 UDP 与浏览器 ICE 分别比较完成" if rtc_status == Status.PASS else "系统 UDP 与浏览器 ICE 需分别查看测量细项",
                                 [{"native_udp": udp_result.status.value, "browser_ice": browser_result.status.value}],
                                 ["两种探测不互相替代；无响应不能证明没有旁路。"]),
                baseline_finding("guard", "守护进程", Status.PASS if guard.get("registered") and guard.get("enabled") and guard.get("running") else Status.UNKNOWN if guard.get("error") else Status.WARN,
                                 "已确认守护任务启用且正在运行" if guard.get("running") and guard.get("enabled") else "守护任务未运行、已停用或尚未安装", [guard], ["进程级轮询保护存在时间窗口，不是防火墙阻断保证。"]),
                baseline_finding("rules", "代理路由规则", Status(rules["status"]), rules["reason"], [rules]),
                language_result,
                baseline_finding("asn", "ASN 信息", Status.PASS if metadata.get("org") else Status.UNKNOWN,
                                 "已取得网络归属资料" if metadata.get("org") else "未取得网络归属资料", [{"organization": metadata.get("org")}], ["机构名称不能可靠证明住宅、代理或托管属性。"])]
    target_ok = bool(targets) and all(t["http_status"] in (200, 204, 301, 302, 307, 308, 401) and not t["error"] for t in targets)
    findings.append(baseline_finding("reachability", "服务连接", Status.PASS if target_ok else Status.WARN if any(t["http_status"] for t in targets) else Status.UNKNOWN,
                                     "已收到服务响应；未验证账号登录" if target_ok else "服务响应需要复核", targets,
                                     ["401、403、429 与服务错误分别保留，不声明账号可用。"] ))
    return findings
