"""Turn independent observations into specific problems and ordered remedies.

Rules describe observed failures. They do not infer bans, account entitlement,
DNS leaks or a process's complete traffic path from incidental configuration.
"""
from urllib.parse import urlsplit
import math

SOURCES = {
    "curl": "https://curl.se/libcurl/c/libcurl-errors.html",
    "network": "https://code.claude.com/docs/en/network-config",
    "errors": "https://platform.claude.com/docs/en/api/errors",
    "settings": "https://code.claude.com/docs/en/settings",
    "troubleshooting": "https://code.claude.com/docs/en/troubleshooting",
    "regions": "https://support.claude.com/en/articles/8461763-where-can-i-access-claude",
}


def diagnose(report, preferences=None):
    preferences = preferences or {}
    findings = report.get("findings", [])
    by_id = {f["id"]: f for f in findings}
    def evidence(key):
        return [v for v in by_id.get(key, {}).get("evidence", []) if isinstance(v, dict)]
    def first(key):
        return next(iter(evidence(key)), {})
    def status(key):
        return by_id.get(key, {}).get("status")
    problems, normal, checks, verification = [], [], [], {}
    usage = preferences.get("usage", "auto")
    def add(key, title, observed, explanation, steps, action="retest", repair=None, priority=2, certainty="confirmed", source="troubleshooting"):
        problems.append({"id": key, "title": title, "observed": observed, "cause": explanation,
                         "steps": steps, "action": action, "repair": repair, "priority": priority,
                         "certainty": certainty, "source": SOURCES[source]})
        verification[key] = "problem"

    region = by_id.get('target.region', {})
    if region:
        verification['target.region'] = 'clear' if region.get('status') == 'pass' else 'unverified'
        if region.get('status') != 'pass':
            add('target.region', region.get('summary', 'Claude 地区条件待核实'), region.get('summary', ''),
                '按官方支持名单分别核对申报地区与出口；中国大陆和俄罗斯不在支持名单。',
                [region.get('suggestion', '')], 'region-support', priority=-1,
                certainty='confirmed' if region.get('status') == 'fail' else 'review', source='regions')

    config = evidence("extra.config")
    for index, target, label in ((0, "desktop", "Claude 桌面配置"), (1, "cli", "Claude Code 用户配置")):
        if usage == 'web' or target == "cli" and usage == "desktop" or target == "desktop" and usage == "cli":
            continue
        shape = config[index] if index < len(config) else {}
        key = "config." + target
        verification[key] = "clear" if shape.get("valid") is True or shape.get("exists") is False else "unverified"
        if shape.get("valid") is False:
            location = (f"第 {shape['line']} 行、第 {shape['column']} 列：" if shape.get("line") and shape.get("column") else "")
            repairable = shape.get("repairable") == "trailing_comma"
            add(key, label + "无法正确读取", location + shape.get("explanation", "文件格式或安全检查未通过"),
                "配置结尾存在多余逗号，解析器无法载入。" if repairable else "文件需要修正后才能载入，不能通过清空配置解决。",
                ["点击“预览可修复内容”，先备份，再移除已确认的多余逗号。", "保存工作并重开对应客户端，再复检。"] if repairable else
                ["备份并打开此配置文件，按上面的行列位置修正。", "保留现有 MCP、认证和其他设置；保存后重开客户端并复检。"],
                action="config-" + target, repair="json-" + target if repairable else None, priority=0, source="settings")
        elif shape.get("error") == "permission_denied":
            add("config_access." + target, label + "没有读取权限", "操作系统拒绝读取现有配置。", "现在无法判断文件是否有效；重新安装并不能证明可修复权限。",
                ["在当前用户下检查文件权限；如果由组织管理，联系管理员恢复读取权限。", "恢复读取权限后重新检测。"], action="config-" + target)
        elif shape.get("error") == "unreadable":
            add("config_read." + target, label + "暂时无法读取", "读取未完成，系统未明确报告权限拒绝。", "文件可能被占用或所在磁盘暂时不可用。",
                ["检查文件与磁盘是否可访问，关闭正在改写配置的程序后重新检测。"], certainty="possible")

    cli = first("extra.cli_env")
    cli_used = usage in ("cli", "both") or usage == "auto" and bool(cli.get("installation_count") or cli.get("config", {}).get("exists"))
    desktop_used = usage in ("desktop", "both") or usage == "auto" and bool(first("extra.desktop").get("found") or first("extra.account").get("tracked"))
    account_used = desktop_used and bool(first("extra.desktop").get("found") or first("extra.account").get("tracked"))
    if usage in ("cli", "both") and cli.get("installation_count") == 0:
        add("cli.installation", "当前 PATH 找不到 Claude Code", "已检查 PATH 中的 Claude 命令入口，没有找到候选文件。", "可能未安装，也可能已安装但终端尚未加载 PATH；不会执行发现的程序来猜测版本。",
            ["如果刚安装过，先完全关闭终端并重新打开。", "仍提示 command not found 时，按官方安装说明检查 PATH 或安装 Claude Code，再复检。"], "cli-install")
    if usage in ("desktop", "both") and first("extra.desktop").get("found") is False:
        add("desktop.installation", "未在已检查位置找到 Claude 桌面版", "常见安装位置与已注册应用中均未确认安装。", "可能尚未安装，也可能安装位置不在本次检查范围；不要删除现有账号资料。",
            ["通过官方桌面下载入口确认并安装对应 Windows / macOS 版本。", "首次打开完成登录后，再运行检测和账号管理。"], "desktop-install")
    bad_cli_config = any(p["id"] == "config.cli" for p in problems)
    bypass = cli.get("proxy_bypass", {})
    cli_bypassed = bool(bypass.get("target_matches") or bypass.get("all_hosts"))
    if preferences.get('environment_confirmed'):
        cli_bypassed = preferences.get('connection_mode') == 'http_proxy' and (
            'api.anthropic.com' in bypass.get('target_matches', []) or bool(bypass.get('all_hosts')))
    cli_rules = [
        ("cli.socks", cli.get("proxy_scheme") in ("socks5", "socks5h"), "Claude Code 配置了不支持的 SOCKS 代理", "当前生效的代理协议是 SOCKS。",
         "curl 可以测试 SOCKS，但 Claude Code 官方仅支持 HTTP / HTTPS 代理；两个结果不能混用。",
         ["使用代理客户端的 HTTP 或 mixed 端口。", "修复方案会先测试已发现的兼容端口，验证 API 可达后才写入 Claude Code 用户配置。", "关闭并重开 Claude Code 会话，让新环境变量生效。"], "cli-proxy"),
        ("cli.proxy_format", cli.get("proxy_valid") is False, "Claude Code 代理地址格式无效", "当前代理变量不能解析为有效地址。", "代理变量有值，但无法作为连接地址使用。",
         ["通过修复方案测试已发现的 HTTP / HTTPS 代理。", "确认后仅更新 Claude Code 用户配置，再重开会话。"], "cli-proxy"),
        ("cli.bypass", cli_bypassed and not cli.get("custom_endpoint"), "Claude Code 的绕过名单匹配了目标服务", "NO_PROXY 匹配所检查的 Anthropic API 目标。",
         "这些请求可能绕过已设置的代理。只有明确需要直连时才应保留对应条目。",
         ["若希望经代理访问，使用修复方案移除 Claude Code 中匹配目标的绕过项。", "其他内部域名条目保留；重开会话后复检。"], "cli-proxy"),
        ("cli.tls_disabled", cli.get("tls_verification_disabled") is True, "Claude Code 的证书验证被关闭", "NODE_TLS_REJECT_UNAUTHORIZED 被设置为 0。", "这会跳过服务端证书验证，不能用于解决网络证书故障。",
         ["修复方案会在 Claude Code 用户配置中恢复证书校验。", "如果使用企业 HTTPS 检查，请取得组织提供的 CA，并配置 NODE_EXTRA_CA_CERTS。", "重开 Claude Code 后复检。"], "cli-tls"),
        ("cli.ca_missing", cli.get("extra_ca_configured") and cli.get("extra_ca_exists") is False, "Claude Code 指定的 CA 文件不存在", "NODE_EXTRA_CA_CERTS 已设置，但没有找到对应文件。", "自定义证书路径失效，可能导致企业代理的证书链不被信任。",
         ["取得组织提供的 CA 文件，修正 NODE_EXTRA_CA_CERTS 指向的本机路径。", "不要下载来源不明的根证书；重开会话后复检。"], None),
        ("cli.endpoint", cli.get("endpoint_valid") is False or cli.get("endpoint_https_or_local") is False, "Claude Code 接口地址格式或协议不合适", "ANTHROPIC_BASE_URL 无法使用，或非本机地址使用了明文 HTTP。", "接口地址需要有效的 HTTP(S) URL；远程服务应使用 HTTPS。",
         ["在配置该变量的位置填写服务提供方给出的完整 HTTPS 地址。", "不要把 API 密钥写进 URL；保存后重开会话。"], None),
        ("cli.providers", cli.get("bedrock") and cli.get("vertex"), "Claude Code 同时启用了两种云提供方", "Bedrock 与 Vertex 开关同时为 1。", "需要先确定实际使用的提供方，避免使用另一套认证和区域配置。",
         ["只保留实际使用的一种提供方开关。", "使用对应云平台的登录方式及模型区域，再重开会话。"], None),
    ]
    for key, condition, title, observed, cause, steps, repair in cli_rules:
        verification[key] = "unverified" if not cli or bad_cli_config else "clear" if not condition else "problem"
        if cli_used and not bad_cli_config and condition:
            add(key, title, observed, cause, steps, "config-cli", repair, source="network")
    if cli_used and cli.get("api_key_present") and cli.get("auth_token_present") and not bad_cli_config:
        add("cli.auth_choice", "Claude Code 同时设置了两种认证变量", "API Key 与 Auth Token 都有值；未读取它们的内容。", "需要核对服务提供方要求哪种认证；仅凭变量存在，不能判断密钥有效或账号异常。",
            ["按服务提供方的要求保留对应认证方式。", "修改后重开会话，再在 Claude Code 中确认登录。"], "config-cli", certainty="review", source="settings")
    if cli_used and isinstance(cli.get("installation_count"), int) and cli["installation_count"] > 1:
        add("cli.multiple_paths", "PATH 中发现多个不同的 Claude Code 入口", f"发现 {cli['installation_count']} 个不同位置的候选入口。",
            "这可能让终端调用到旧安装；多个入口本身不证明当前命令有故障。",
            ["在 Claude Code 中运行 /doctor，核对实际加载的安装和版本。", "按官方安装说明保留需要的安装来源并调整 PATH，再重开终端。工具不会执行未知入口或自动卸载程序。"], "cli-install", certainty="review")
    verification["cli.multiple_paths"] = "clear" if cli.get("installation_count") == 1 else "unverified"

    responses = evidence("baseline.reachability")
    if not responses:
        responses = [r for r in evidence("extra.tls") if urlsplit(r.get("endpoint", "")).hostname in ("claude.ai", "api.anthropic.com")]
    if preferences.get('environment_confirmed'):
        from .target_environment import selected_hosts
        responses = [r for r in responses if urlsplit(r.get('endpoint', '')).hostname in selected_hosts(preferences)]
    errors = {r.get("error") for r in responses if r.get("error")}
    for key in ("http.egress", "browser.http_v4"):
        errors.update(r.get("error") for r in evidence(key) if r.get("error"))
    code = lambda n: "curl_exit_" + str(n) in errors
    clock = first("extra.clock")
    skew = clock.get("offset_seconds")
    skew = skew if isinstance(skew, (int, float)) and not isinstance(skew, bool) and math.isfinite(skew) else None
    clock_bad = skew is not None and abs(skew) > 120
    verification["clock.offset"] = "problem" if clock_bad else "clear" if skew is not None else "unverified"
    if clock_bad:
        add("clock.offset", "系统时间与网络时间相差过大", f"多个 HTTPS 日期给出的中位偏差约 {abs(round(skew))} 秒。", "时间偏差可能影响证书有效期与登录；这来自 HTTP 日期比较，并非可信 NTP 校时。",
            ["打开系统日期与时间设置，启用自动设置时间并执行同步。", "时间同步后重新检测；若证书仍失败，再处理证书链。"], "clock-settings", priority=0, source="network")
    tls_bad = status("target.tls" if preferences.get('environment_confirmed') else "extra.tls") == "fail" or any(code(n) for n in (51, 60, 77, 83))
    verification["network.certificate"] = "problem" if tls_bad else "clear" if status("extra.tls") == "pass" else "unverified"
    if tls_bad and not clock_bad:
        add("network.certificate", "HTTPS 证书校验失败", "探测收到证书验证错误" + ("（curl 77：CA 文件读取失败）。" if code(77) else "（curl 51 / 60 / 83 或证书校验未通过）。"),
            "证书信任链、系统时间或企业 HTTPS 检查需要核对；不能从这个错误推断账号被封禁。",
            ["先检查系统日期与时间。", "企业网络请使用组织提供的 CA；Claude Code 用 NODE_EXTRA_CA_CERTS 指向该文件。", "保持证书验证开启，修正后复检。"], "clock-settings", priority=0, source="curl")
    listeners = evidence("extra.proxy_listener")
    closed = [r for r in listeners if r.get("tcp_accepts") is False]
    verification["proxy.listener"] = "problem" if closed else "clear" if listeners and all(r.get("tcp_accepts") is True for r in listeners) else "unverified"
    if closed:
        add("proxy.listener", "配置的本机代理端口没有接受连接", f"已配置端口中有 {len(closed)} 个没有接受本机 TCP 连接。", "可能是客户端未启动、监听端口已变化或请求被本机策略阻止；还不能判断远端节点是否可用。",
            ["打开代理客户端，确认其正在运行。", "核对 HTTP / mixed 端口，点击“测试已发现代理”直接验证。", "端口恢复后重新检测，无需先重装 Claude。"], "proxy-test", priority=0, source="curl")
    elif code(5):
        add("network.proxy_dns", "代理服务器名称无法解析", "curl 返回错误 5。", "失败发生在解析代理服务器名称阶段，尚未连接 Claude。",
            ["核对代理地址的主机名、拼写和网络连接。", "本机代理请优先使用客户端显示的 loopback HTTP / mixed 地址，再测试代理。"], "proxy-test", source="curl")
    elif code(6):
        add("network.dns", "目标域名无法解析", "curl 返回错误 6。", "请求在域名解析阶段失败，尚未进入 TLS 或账号认证。",
            ["确认代理客户端的 DNS 功能已运行，检查是否有目标域名 hosts 覆盖。", "使用“测试已发现代理”比较代理路径；修正 DNS 设置后复检。"], "proxy-test", source="curl")
    elif code(7):
        add("network.connect", "连接没有建立", "curl 返回错误 7，未建立到目标或代理的 TCP 连接。", "需要区分代理地址失效与目标路径不可达；当前证据不足以归因到账号。",
            ["先用“测试已发现代理”检查现有代理路径。", "若代理路径也失败，检查客户端节点、端口和本机防火墙；不要重复重装 Claude。"], "proxy-test", source="curl")
    elif code(35):
        add("network.handshake", "HTTPS 握手未完成", "curl 返回错误 35。", "TCP 后的 TLS 握手失败；可能涉及中间代理、TLS 配置或证书。",
            ["测试已发现的代理，比较是否只有某条路径失败。", "核对组织的 HTTPS 检查设置和 CA 配置，再复检。"], "proxy-test", source="curl")
    elif code(28) or errors & {"deadline_exceeded"}:
        add("network.timeout", "连接在等待期限内没有完成", "请求超时，没有得到完整响应。", "超时本身无法区分代理故障、目标不可达或检测端点繁忙。",
            ["测试已发现的代理，查看是否能收到 Claude API 响应。", "如果浏览器能用而系统探测超时，优先核对两者代理路径；稍后再复检。"], "proxy-test", certainty="review", source="curl")
    if "curl_unavailable" in errors:
        add("network.curl", "系统找不到 curl 检测组件", "系统 HTTP 检查无法启动 curl。", "这是检测组件缺失，不能据此判断 Claude 网络不可用。",
            ["Windows 10/11 和 macOS 通常已附带 curl，检查系统目录和 PATH 是否被裁剪。", "使用完整桌面包重新启动；如仍缺失，恢复系统 curl 后复检。"], priority=0, source="curl")
    if any(code(n) for n in (18, 52, 55, 56)) and not any(r.get("http_status") == 407 for r in responses) and not closed:
        add("network.interrupted", "请求传输中断或响应为空", "curl 没有取得完整服务响应。", "连接被关闭、接收失败或响应内容不完整；尚不能确定中断发生在哪一段。",
            ["测试已发现的代理，比较是否仅一条路径中断。", "检查节点连接及组织网络策略；如果官方服务也异常，等待恢复后复检。"], "proxy-test", certainty="review", source="curl")

    responded = bool(responses) and all(not r.get("error") and isinstance(r.get("http_status"), int) and 100 <= r["http_status"] <= 599 for r in responses)
    for key in ("network.proxy_dns", "network.dns", "network.connect", "network.handshake", "network.timeout", "network.curl", "network.interrupted"):
        verification[key] = "problem" if any(p["id"] == key for p in problems) else "clear" if responded else "unverified"
    target_timings = [r for r in evidence("extra.timing") if urlsplit(r.get("endpoint", "")).hostname in ("claude.ai", "api.anthropic.com")
                      and isinstance(r.get("total_ms"), (int, float)) and math.isfinite(r["total_ms"]) and r["total_ms"] >= 0]
    slow = [r for r in target_timings if r["total_ms"] >= 3000]
    verification["performance.latency"] = "clear" if not slow and {urlsplit(r["endpoint"]).hostname for r in target_timings} == {"claude.ai", "api.anthropic.com"} else "unverified"
    if slow and not errors and not closed:
        sample = max(slow, key=lambda r:r["total_ms"])
        phases = [(name, sample.get(key)) for name, key in (("DNS 解析", "dns_ms"), ("TCP 连接", "tcp_ms"), ("TLS 握手", "tls_ms"))]
        phases = [(name, value) for name, value in phases if isinstance(value, (int,float)) and math.isfinite(value) and value >= 0]
        if isinstance(sample.get("first_byte_ms"), (int,float)) and math.isfinite(sample["first_byte_ms"]):
            phases.append(("等待首字节", max(0, sample["first_byte_ms"] - sum(value for _,value in phases))))
        phase, elapsed = max(phases, key=lambda p:p[1]) if phases else ("总耗时",sample["total_ms"])
        add("performance.latency", "本次 Claude 连接耗时较长", f"单次请求总耗时约 {round(sample['total_ms'])} ms；主要耗时阶段为{phase}（约 {round(elapsed)} ms）。",
            "耗时包含代理、网络与服务处理，单次结果不能确定远端节点或服务端谁是根因。",
            ["使用“测试已发现代理”比较当前代理路径。", "DNS 阶段长则核对解析设置；连接 / 握手长则检查节点路径；首字节等待长则同时查看服务状态。", "在相近时间复测，避免凭一次结果反复重装或更改系统设置。"], "proxy-test", certainty="review", source="curl")
    verification["cli.auth_choice"] = "unverified" if not cli or bad_cli_config else "clear" if not (cli.get("api_key_present") and cli.get("auth_token_present")) else "problem"

    for r in responses:
        host = urlsplit(r.get("endpoint", "")).hostname
        label = "Claude 网页" if host == "claude.ai" else "Claude API" if host == "api.anthropic.com" else "目标服务"
        status_code = r.get("http_status", 0)
        if not r.get("error") and status_code == 401 and host == "api.anthropic.com":
            normal.append("Claude API 已响应。本工具未发送密钥，401 是认证要求，不是发现密钥失效。")
        elif not r.get("error") and status_code in (200, 204, 301, 302, 307, 308):
            normal.append(label + "已返回响应，网络请求已到达服务；未验证实际登录和模型调用。")
        elif status_code in (403, 407, 429) or isinstance(status_code, int) and status_code >= 500:
            key = "service." + (host or "target") + "." + str(status_code)
            if any(p["id"] == key for p in problems):
                continue
            if status_code == 407:
                title, why = "代理服务器要求认证", "代理返回 407，请求尚未完成代理认证。"
                steps = ["在代理客户端或组织指定位置配置正确的代理认证。", "重新测试该代理；不要把此结果当成 Claude 账号认证失败。"]
            elif status_code == 403:
                title, why = label + "拒绝了本次自动探测", "HTTP 403 可能来自访问校验、访问策略或权限；未发送账号凭据，不能判断封禁原因。"
                steps = ["在常用浏览器中打开 Claude，完成网页要求的访问校验。", "如果实际客户端也返回 403，核对组织权限、服务支持范围或联系服务支持。", "无需先修改时区、语言或反复更换账号。"]
            elif status_code == 429:
                title, why = label + "返回限流响应", "HTTP 429 说明本次请求受到限制；无认证探测不能区分请求限额与账号额度。"
                retry = r.get("retry_after_seconds")
                steps = ([f"服务要求至少等待 {retry} 秒，再复检。"] if isinstance(retry, int) else ["暂停连续重试，稍后再检测。"])
                steps += ["若登录后的真实请求仍受限，在 Claude Console 核对限额和用量；此情况不靠重装软件解决。"]
            else:
                title, why = label + "返回服务端错误", f"收到 HTTP {status_code}；本次失败发生在服务响应阶段，不应先归咎于本机配置。"
                steps = ["查看官方服务状态，等待服务恢复后复检。", "若状态正常但持续失败，记录时间与状态码联系服务支持；避免循环修复本机设置。"]
            add(key, title, f"{label}收到 HTTP {status_code}。", why, steps,
                "service-status" if status_code >= 500 or status_code == 429 else "claude-web" if status_code == 403 else "proxy-test", source="errors")

    account = first("extra.account")
    for host in ("claude.ai", "api.anthropic.com"):
        usable = [r for r in responses if urlsplit(r.get("endpoint", "")).hostname == host]
        healthy = any(not r.get("error") and r.get("tls_verified") is True and r.get("http_status") in ((200, 204, 301, 302, 307, 308, 401) if host == "api.anthropic.com" else (200, 204, 301, 302, 307, 308)) for r in usable)
        for number in (403, 407, 429, *range(500, 600)):
            key = f"service.{host}.{number}"
            verification[key] = "clear" if healthy else "unverified"
    verification["account.integrity"] = "clear" if account.get("valid") is True and not account.get("pending") else "unverified"
    if (not preferences.get('environment_confirmed') or desktop_used) and (account.get("valid") is False or account.get("pending")):
        add("account.integrity", "账号资料处于需要恢复的状态", "账号标记不一致。" if account.get("valid") is False else "发现上次交换遗留的事务或副本。",
            "继续交换可能覆盖可恢复的资料，当前已保留副本。",
            ["停止账号切换，保留 .new / .previous 目录和事务日志。", "从账号页核对当前槽位与存档；导出诊断包后再按副本恢复，不运行清理或强制覆盖。"], "accounts", priority=0)
    space = first("extra.storage").get("free_bytes")
    verification["storage.low"] = "clear" if isinstance(space, int) and space >= 512 * 1024 ** 2 else "unverified"
    if usage != 'web' and isinstance(space, int) and space < 512 * 1024 ** 2:
        add("storage.low", "资料磁盘可用空间不足", f"当前约剩余 {round(space / 1024 ** 2)} MiB，低于 512 MiB 提示下限。", "账号备份和事务复制需要额外空间，当前可能无法完成。",
            ["打开系统存储设置，清理已确认不再需要的其他文件。", "保留 Claude 账号目录、备份及事务副本；腾出空间后复检。"], "storage-settings", priority=0)
    hosts = first("extra.hosts")
    verification["hosts.override"] = "clear" if hosts.get("readable") is True and not hosts.get("overrides") else "unverified"
    if hosts.get("overrides"):
        add("hosts.override", "本机 hosts 改写了目标域名", f"发现 {len(hosts['overrides'])} 条目标域名映射。", "映射会覆盖普通域名解析；如果是有意设置，可保留，不直接认定为故障。",
            ["打开 hosts 文件，核对 Claude / Anthropic 条目是否仍需要。", "如非预期，先备份再由有权限的编辑器移除对应条目，随后复检。"], "hosts-file", certainty="review")
    bind = first("extra.controller_bind")
    verification["proxy.controller"] = "clear" if bind.get("loopback_bind") is True else "unverified"
    if bind.get("wildcard_bind") or bind.get("loopback_bind") is False:
        add("proxy.controller", "代理控制接口配置为非本机监听", "控制接口的监听地址没有限制为 loopback。", "这扩大了管理接口的配置访问范围；尚未测试其他设备是否可达。",
            ["如果仅用于本机管理，在代理客户端中将 external-controller 设置为 127.0.0.1 上的端口。", "配置控制口认证后复检；不要公开控制口密钥。"], "proxy-settings", certainty="review")
    for key, pref, label in (("country", "country", "出口国家"), ("timezone", "timezone", "系统时区"), ("locale", "locale", "地区格式"), ("language", "locale", "客户端语言")):
        f = first("baseline." + key)
        if status("baseline." + key) == "fail" and preferences.get(pref):
            add("target." + key, label + "与您设置的目标不同", f"当前：{f.get('actual', '未取得')}；目标：{f.get('expected', preferences[pref])}。",
                "这说明与所选偏好不一致，不代表账号风险；不需要美国时区或英语才能使用本工具。",
                ["如果当前值符合实际需要，在设置页修正比较目标。", "如果确需改变系统偏好，请在对应系统设置中调整后复检。"], "settings", certainty="review")
        verification["target." + key] = "clear" if not preferences.get(pref) or status("baseline." + key) == "pass" else "unverified"
    for key in ("http.egress", "http.ipv6", "udp.stun", "browser.webrtc", "browser.http_v4", "browser.http_v6"):
        if status(key) == "fail":
            f = by_id[key]
            add("policy." + key, f["title"] + "超出允许范围", "本次观测地址未匹配您明确填写的允许网段。", "这是与这份地址策略不符，不是对地址归属、住宅属性或实际位置的判断。",
                ["在代理客户端检查分流规则、IPv4 / IPv6 与 UDP 路径。", "仅在确认策略本身写错时修改允许网段，不要把当前待测地址直接当成可信地址。", "调整后重新检测。"], "settings", priority=0)
        verification["policy." + key] = "clear" if status(key) == "pass" else "unverified"
    guard = first("baseline.guard")
    if account_used and preferences.get("require_guard") and guard and not guard.get("error") and not (guard.get("registered") and guard.get("enabled") and guard.get("running")):
        add("maintenance.guard", "账号启动要求的守护任务没有运行", "设置中要求守护任务，但本次未确认它启用并运行。", "这一条件会阻止账号启动；守护不是防火墙隔离保证。",
            ["预览原生进程守护；先通过目标选路核对，再使用实际接口或已确认的本机代理端口。", "批准后台自动停止范围后，等待新心跳并复检；注册任务本身不能算守护已运行。"], "maintenance", "guard", source="troubleshooting")
    rule = first("baseline.rules")
    if account_used and preferences.get("require_rules") and status("baseline.rules") in ("warn", "fail"):
        reason = rule.get("reason", "运行规则未满足选定条件。")
        expected, actual = rule.get("expected_rule", {}), rule.get("actual_rule", {})
        observed = reason
        if expected:
            observed += f"；第 {expected['position']} 条预期匹配 {expected['value']} → {expected['target']}，实际为 {actual.get('type','未取得')} {actual.get('payload','')} → {actual.get('target','未取得')}。"
        if "UDP" in reason or "节点" in reason or "循环" in reason or "直连模式" in reason:
            add("maintenance.rules", "账号启动所需的代理节点或模式不满足", observed,
                "运行内核当前没有报告满足所选策略的节点 / 模式。重写规则不一定能解决节点选择问题。",
                ["在代理客户端切换到预期的规则或全局模式，选择真实代理节点。", "需要代理 UDP 时选择明确支持 UDP 的节点；不要把 DIRECT / REJECT 当成代理节点。", "完成后复检，核对实际运行状态。"], "proxy-settings")
        else:
            add("maintenance.rules", "账号启动要求的代理规则不满足", observed, "需要修正运行内核中的规则；静态配置文本存在不能代替实际加载。",
                ["在修复方案或持续维护中预览原生路由配置：备份、保留脚本、重载并读回 16 条规则。", "不支持的客户端请将所列条目放进实际加载的规则；静态文件不能证明已经生效。"], "maintenance", "routing")
    elif account_used and preferences.get("require_rules") and status("baseline.rules") == "unknown":
        group_missing = "代理组" in rule.get("reason", "")
        add("startup.rules", "账号启动要求核对规则，但本次没有完成", rule.get("reason", "没有取得可识别的代理运行规则。"),
            "没有自动识别出唯一的目标代理组；不是发现了节点泄漏。" if group_missing else "这会阻止账号启动，但不单独说明当前连接有故障。可能是控制接口未开启、需要认证，或客户端不兼容。",
            ["在设置页的“目标代理组”填写客户端中实际使用的组名，然后复检。" if group_missing else "在代理客户端核对本机控制接口与认证设置，再复检。",
             "如果实际客户端不提供兼容接口，请在设置中明确调整“启动前要求代理运行规则通过核对”，不要把未检测当成通过。"], "settings", certainty="review")
    if account_used and status("baseline.tun") != "pass" and (not preferences.get('environment_confirmed') or preferences.get('connection_mode') == 'tun'):
        add("startup.tun", "账号启动策略要求 TUN，目前没有确认", "本次未确认符合当前账号启动策略的 TUN 接口。",
            "网页或 CLI 可以经系统代理连接；账号交换仍按当前严格启动条件检查 TUN。",
            ["如果使用账号切换，在代理客户端启用所需 TUN / 服务模式并完成系统授权。", "随后重新检测；普通网页和 CLI 使用不需要为此交换账号。"], "proxy-settings", certainty="review")
    verification["startup.rules"] = "clear" if status("baseline.rules") == "pass" or not preferences.get("require_rules") else "unverified"
    verification["startup.tun"] = "clear" if status("baseline.tun") == "pass" else "unverified"
    for key in ("maintenance.guard", "maintenance.rules"):
        finding_key = "baseline.guard" if key.endswith("guard") else "baseline.rules"
        verification[key] = "problem" if any(p["id"] == key for p in problems) else "clear" if status(finding_key) == "pass" else "unverified"

    for f in findings:
        key, text = f["id"], f["summary"]
        state = "checked" if f["status"] == "pass" else "reference" if f["status"] == "skipped" else "unmeasured" if f["status"] == "unknown" else "reference"
        setting = first(key)
        if key in ("baseline.country", "baseline.timezone", "baseline.locale") and not setting.get("expected"):
            text, state = "当前：" + str(setting.get("actual") or "未取得") + "；未设置比较目标，无需按此项改动系统。", "reference"
        elif key == "baseline.ip_stability" and f["status"] == "unknown":
            text, state = "尚无可比较的上次出口；不是发现了出口变化。", "reference"
        elif key == "dns.leak":
            text, state = "本版未测量实际 DNS 出口；这不等于发现了 DNS 泄漏。", "unsupported"
        elif key == "network.route":
            text, state = "本版未跟踪目标进程全流量；系统选路由扩展检查单独报告。", "unsupported"
        elif key == "extra.runtime_tun" and f["status"] != "pass":
            text, state = "没有确认 TUN 已开启。使用系统代理时不必据此改动；若期望 TUN，请在代理客户端核对。", "reference"
        elif key == "extra.target_route" and f["status"] != "pass":
            text, state = "系统选路未全部指向隧道；系统代理模式下可出现此结果，不单独作为故障。", "reference"
        elif key == "extra.proxy_layers" and f["status"] == "warn":
            text, state = "系统代理与环境代理配置不同；结合上方连接结果决定是否处理。", "reference"
        elif key == "extra.cli_paths" and first(key).get("candidate_count") == 0:
            text, state = "PATH 中没有 CLI；只使用桌面版无需安装。", "reference"
        elif key == "extra.config" and all(not r.get("exists") for r in config):
            text, state = "可选 JSON 配置未创建，不需要修复。", "reference"
        elif key == "baseline.language" and f["status"] == "unknown":
            text, state = "未读取到应用语言偏好；无需因此修改系统语言。", "reference"
        checks.append({"id": key, "title": f["title"], "state": state, "text": text})
    if preferences.get('environment_confirmed'):
        required = set(report['environment']['required'])
        for f in findings:
            if not f['id'].startswith('target.') or f['id'] not in required:
                continue
            if f['id'] == 'target.region':
                continue
            verification[f['id']] = 'clear' if f['status'] == 'pass' else 'unverified'
            if f['status'] == 'pass':
                continue
            key = f['id'].split('.', 1)[1]
            repair = ('cli-direct' if preferences['connection_mode'] in ('direct', 'tun') else 'cli-proxy') if key == 'cli_path' else None
            action = 'config-cli' if key in ('cli_path', 'provider', 'auth') else 'proxy-settings' if key in ('path', 'ipv6') else 'clock-settings' if key == 'clock' else 'retest'
            if key == 'config' and any(p['id'].startswith(('config.', 'config_access.', 'config_read.')) for p in problems):
                continue
            if key == 'service' and any(p['id'].startswith('service.') for p in problems):
                continue
            add(f['id'], f['title'], f['summary'], '此项属于已确认目标，必须有相应证据才能完成验收。', [f.get('suggestion') or '补全对应配置并重新检测。'], action, repair,
                certainty='confirmed' if f['status'] == 'fail' else 'review')
    problems.sort(key=lambda p: (p["priority"], p["id"]))
    if problems:
        headline = f"发现 {len(problems)} 个需要处理的问题"
        summary = "先处理：" + problems[0]["title"] + "。下方已列出原因、步骤和可执行入口。"
        state = "issues"
    elif normal:
        headline, summary, state = "Claude 服务已返回响应", "本次没有定位到可确认的连接故障。未发送登录凭据，不能据此确认账号或模型权限。", "responding"
    else:
        headline, summary, state = "本次未取得足够的连接结果", "尚未定位到具体故障，先重新检测；若仍没有响应，可直接测试已发现的代理。", "unavailable"
    return {"schema_version": 1, "headline": headline, "summary": summary, "state": state,
            "problems": problems, "normal": list(dict.fromkeys(normal)), "checks": checks,
            "verification": verification, "repairable_count": sum(bool(p.get("repair")) for p in problems),
            "coverage": "实际 DNS 出口与目标进程全流量尚未验证；该能力缺口不计为本机故障。"}


def compare_diagnoses(before, after):
    result = {"resolved": [], "remaining": [], "unverified": [], "new": []}
    old = {p["id"]: p for p in before.get("problems", [])}
    new = {p["id"]: p for p in after.get("problems", [])}
    for key, problem in old.items():
        field = "remaining" if key in new else "resolved" if after.get("verification", {}).get(key) == "clear" else "unverified"
        result[field].append({"id": key, "title": problem["title"]})
    result["new"] = [{"id": key, "title": problem["title"]} for key, problem in new.items() if key not in old]
    return result
