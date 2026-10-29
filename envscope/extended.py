"""Nineteen additional checks, each restricted to the evidence actually measured."""
import ipaddress
import re
import statistics
from urllib.parse import urlsplit

from .model import Finding, Status

CHECKS = (("dns_resolution", "目标域名解析"), ("target_route", "目标系统选路"), ("hosts", "hosts 覆盖"),
          ("proxy_layers", "代理配置一致性"), ("proxy_bypass", "代理绕过名单"), ("proxy_listener", "本地代理监听"),
          ("runtime_tun", "内核 TUN 运行配置"), ("controller_bind", "控制接口监听配置"),
          ("tls", "TLS 证书校验"), ("timing", "连接分段耗时"), ("clock", "系统时间偏差"),
          ("desktop", "桌面客户端安装"), ("profile", "客户端资料目录"), ("config", "客户端配置格式"),
          ("cli_paths", "CLI 入口冲突"), ("cli_env", "CLI 认证与接口配置"),
          ("storage", "资料磁盘空间"), ("account", "账号存档一致性"), ("ecosystem", "外围服务 HTTPS 连接"))


def extended_checks(inventory, network, local, context):
    result = []
    from .ecosystem import finding
    result.append(finding(context.get('ecosystem', [])))
    titles = dict(CHECKS)
    def add(name, status, summary, evidence=(), limits=(), suggestion="", scope="selected-configuration-only"):
        result.append(Finding("extra." + name, titles[name], status, summary, scope, list(evidence), list(limits), suggestion))
    dns = network.get("dns", [])
    valid_dns = []
    for r in dns:
        if not isinstance(r, dict) or r.get("host") not in ("claude.ai", "api.anthropic.com") or not isinstance(r.get("addresses"), list) or not r["addresses"] or r.get("complete") is not True:
            continue
        try:
            if all(isinstance(ip, str) and ipaddress.ip_address(ip) for ip in r["addresses"]):
                valid_dns.append(r)
        except ValueError:
            pass
    complete_dns = {r["host"] for r in valid_dns} == {"claude.ai", "api.anthropic.com"}
    ips = []
    for r in valid_dns:
        for value in r["addresses"]:
            try:
                ips.append(ipaddress.ip_address(value))
            except ValueError:
                pass
    suspicious = any((ip.is_private or ip.is_loopback or ip.is_link_local) and not (ip.version == 4 and ip in ipaddress.ip_network("198.18.0.0/15")) for ip in ips)
    add("dns_resolution", Status.WARN if suspicious else Status.PASS if complete_dns and ips else Status.UNKNOWN,
        "解析结果包含需复核的本地地址" if suspicious else "两个目标域名已取得系统解析结果" if complete_dns else "解析结果不完整，不能作出判断", dns,
        ["Fake-IP 是映射线索；系统解析成功不证明实际 DNS 出口没有旁路。"],
        "核对代理客户端 DNS 设置、hosts 和网络连接后复测。", "system-resolver-two-hosts")
    adapters = inventory.get("network", {}).get("adapters", [])
    tunnel_names = set()
    tunnel_indexes = set()
    for a in adapters if isinstance(adapters, list) else []:
        if re.search(r"TUN|TAP|Wintun|WireGuard|VPN|Tailscale|utun", str(a.get("InterfaceDescription", a.get("name", ""))), re.I):
            name = a.get("Name", a.get("name"))
            if isinstance(name, str) and name:
                tunnel_names.add(name)
            index = a.get("ifIndex")
            if isinstance(index, int) and not isinstance(index, bool) and index > 0:
                tunnel_indexes.add(str(index))
    routes = network.get("routes", [])
    available = [r for r in routes if isinstance(r, dict) and (r.get("interface") or
                 isinstance(r.get("interface_index"), int) and not isinstance(r.get("interface_index"), bool) and r["interface_index"] > 0) and not r.get("error")]
    through_tunnel = [r for r in available if str(r.get("interface")) in tunnel_names or str(r.get("interface_index")) in tunnel_indexes]
    expected = {next((ip for ip in r["addresses"] if ipaddress.ip_address(ip).version == family), None) for r in valid_dns for family in (4, 6)} - {None}
    complete_routes = expected <= {r.get("destination") for r in available}
    all_tunnel = complete_dns and complete_routes and bool(available) and len(through_tunnel) == len(routes) and not any(re.search(r"REJECT|BLACKHOLE", r.get("flags", ""), re.I) for r in available)
    add("target_route", Status.PASS if all_tunnel else Status.WARN if available else Status.UNKNOWN,
        "已检查的目标地址由系统选择隧道接口" if all_tunnel else "选路存在物理接口、缺失或其他需要复核的情况" if available else "未取得目标地址的系统选路", routes,
        ["每个目标和地址族最多检查一个解析地址；这是系统选路，不是 Claude 进程套接字或数据包证明。"],
        "确认使用系统代理还是 TUN；若期望 TUN，检查自动路由及 IPv6 路径。", "os-selected-route-sample")
    hosts = local.get("hosts", {})
    add("hosts", Status.UNKNOWN if not hosts.get("readable") else Status.WARN if hosts.get("overrides") else Status.PASS,
        "目标域名存在本地 hosts 覆盖" if hosts.get("overrides") else "未发现目标域名的 hosts 覆盖" if hosts.get("readable") else "hosts 文件未能读取", [hosts],
        ["只核对 Claude 网页与 API 两个目标，不导出其他 hosts 内容。"], "确认覆盖是否有意设置；保留原文件备份后再处理。")
    proxy = local.get("proxy", {})
    system = proxy.get("system", {})
    differences = bool(system.get("available")) and set(system.get("endpoints", [])) != set(proxy.get("environment", []))
    dynamic = system.get("pac_configured") or system.get("auto_detect") or "auto_detect" in system and system["auto_detect"] is None
    add("proxy_layers", Status.WARN if differences or proxy.get("invalid_environment_count") else Status.UNKNOWN if dynamic or not system.get("available") else Status.PASS,
        "系统与环境代理配置存在差异" if differences else "动态代理配置存在或尚未完整取得" if dynamic else "系统代理配置未完整取得" if not system.get("available") else "已比较系统与环境代理配置", [proxy],
        ["只核对当前用户系统代理与环境变量，不覆盖 WinHTTP 或每个应用；自动检测标记缺失时保留未知。PAC/WPAD 不获取或执行。"],
        "核对系统代理、HTTP(S)_PROXY 与 TUN 模式；使用工具页分别验证指定代理。")
    bypass = [system.get("bypass", {}), proxy.get("environment_bypass", {})]
    bypassed = any(r.get("target_matches") or r.get("all_hosts") for r in bypass)
    add("proxy_bypass", Status.WARN if bypassed else Status.PASS if system.get("available") else Status.UNKNOWN,
        "绕过名单包含目标域名或通配全部" if bypassed else "已检查的绕过名单未匹配目标" if system.get("available") else "尚未取得完整绕过名单配置", bypass,
        ["只导出匹配结果与数量；不公开其他内部域名。"], "检查 NO_PROXY、系统例外名单和预期的分流规则。")
    listeners = local.get("listeners", [])
    add("proxy_listener", Status.PASS if listeners and all(r.get("tcp_accepts") is True for r in listeners) else Status.WARN if listeners else Status.UNKNOWN,
        "发现的本机端口接受 TCP 连接" if listeners and all(r.get("tcp_accepts") is True for r in listeners) else "本地监听未确认或部分端口未接受连接", listeners,
        ["最多探测 4 个已配置的 loopback 端口，不扫描；TCP 接受不证明代理协议正常。"],
        "确认客户端已启动及监听端口；仅使用 TUN 时可不配置本地 HTTP 代理。", "configured-loopback-tcp")
    runtime = context.get("runtime", {})
    tun_enabled = runtime.get("tun_enabled")
    add("runtime_tun", Status.PASS if tun_enabled is True else Status.WARN if tun_enabled is False else Status.UNKNOWN,
        "内核报告 TUN 已启用" if tun_enabled is True else "内核 TUN 关闭或未能读取运行配置", [runtime],
        ["内核声明不等于目标进程全流量接管；非兼容控制接口的客户端可能无法读取。"], "结合目标选路和实际出口核对客户端的 TUN / 自动路由设置。", "loopback-runtime-config")
    controller = local.get("controller", {})
    exposed = controller.get("wildcard_bind") or controller.get("loopback_bind") is False
    add("controller_bind", Status.WARN if exposed else Status.PASS if controller.get("loopback_bind") is True else Status.UNKNOWN,
        "控制接口未限定本机监听，需复核访问范围" if exposed else "控制接口配置为 loopback 监听" if controller.get("loopback_bind") is True else "控制接口监听范围未确认", [controller],
        ["不扫描其他主机，不据配置推断防火墙状态或接口实际可达范围。"], "若仅供本机管理，核对 loopback 监听与控制口密钥。")
    responses = context.get("responses", [])
    verified = [r for r in responses if r.get("tls_verified") is True and not r.get("error")]
    bad = any(r.get("tls_verified") is False for r in responses)
    add("tls", Status.FAIL if bad else Status.PASS if responses and len(verified) == len(responses) else Status.WARN if verified else Status.UNKNOWN,
        "探测端点证书校验均通过" if responses and len(verified) == len(responses) else "发现证书校验失败" if bad else "证书校验观测不完整", responses,
        ["使用 curl 当前信任库；不关闭校验，不认证服务端账号。"],
        "检查系统时间、系统信任证书和代理的 HTTPS 检查设置；不要通过关闭证书验证来掩盖问题。", "curl-peer-verification")
    timings = [{"endpoint": r.get("endpoint"), **r["timings"]} for r in responses if r.get("timings") and not r.get("error")]
    slow = any(r.get("total_ms", 0) >= 3000 for r in timings)
    add("timing", Status.WARN if slow else Status.PASS if timings and len(timings) == len(responses) else Status.UNKNOWN,
        "部分请求耗时达到 3 秒" if slow else "已记录 DNS、TCP、TLS、首字节与总耗时" if timings else "没有完整耗时观测", timings,
        ["单次测量包含代理与服务端处理；3 秒是排障提示阈值，不是服务可用性标准。"], "查看主要耗时阶段，再比较指定代理；不自动切换节点或回退直连。", "single-request-timing")
    clock_sources = {urlsplit(r.get("endpoint", "")).hostname: r["clock_offset_seconds"] for r in responses
                     if isinstance(r.get("clock_offset_seconds"), (int, float)) and r.get("tls_verified") is True and urlsplit(r.get("endpoint", "")).scheme == "https"}
    offsets = list(clock_sources.values())
    consistent = len(offsets) >= 2 and max(offsets) - min(offsets) <= 30
    offset = round(statistics.median(offsets), 1) if consistent else None
    add("clock", Status.UNKNOWN if offset is None else Status.WARN if abs(offset) > 120 else Status.PASS,
        "系统时间与多个 HTTPS 响应日期存在明显偏差" if offset is not None and abs(offset) > 120 else "多个 HTTPS 日期与系统时间大致一致" if consistent else "日期样本不足或来源相互不一致", [{"offset_seconds": offset, "sample_count": len(offsets)}],
        ["修正缓存 Age；HTTP 日期不是可信 NTP，不自动修改系统时间。"], "核对系统自动校时；样本不足时稍后复测。", "https-date-comparison")
    add("desktop", Status.PASS if local.get("installed") is True else Status.UNKNOWN,
        "在已检查位置发现 Claude 桌面安装" if local.get("installed") else "未在已检查位置确认桌面安装", [{"found": local.get("installed")}],
        ["检查已注册 Windows 包或常见安装位置；不启动客户端。"], "如需桌面账号切换，先确认客户端安装；仅使用 CLI 时此项可忽略。")
    add("profile", Status.PASS if local.get("profile_exists") else Status.UNKNOWN,
        "客户端资料目录存在" if local.get("profile_exists") else "尚未发现客户端资料目录", [{"exists": local.get("profile_exists")}],
        ["目录存在不代表已登录、会话有效或系统凭据已迁移。"], "首次使用需打开客户端完成登录；不要手动覆盖现有资料。")
    configs = [local.get("desktop_config", {}), local.get("cli", {}).get("config", {})]
    exists = [c for c in configs if c.get("exists")]
    add("config", Status.WARN if any(c.get("valid") is False for c in exists) else Status.UNKNOWN if any(c.get("valid") is not True for c in exists) else Status.PASS if exists else Status.SKIPPED,
        "发现无效或不支持的配置格式" if any(c.get("valid") is False for c in exists) else "已存在的客户端 / CLI 配置为有效 JSON 对象" if exists else "未配置可选 JSON 文件", configs,
        ["只检查格式与 MCP 数量，不读取或导出命令参数、环境密钥；有效 JSON 不等于 MCP 可连接。"], "备份后检查 JSON 格式及 MCP 配置结构，不直接删除配置文件。")
    cli = local.get("cli", {})
    count = cli.get("installation_count", 0)
    add("cli_paths", Status.WARN if count > 1 else Status.PASS if count == 1 else Status.SKIPPED,
        "PATH 中发现多个 CLI 候选入口" if count > 1 else "PATH 中发现一个 CLI 候选入口" if count == 1 else "未发现 CLI 入口；桌面使用可忽略", [{"candidate_count": count, "origins": cli.get("origins", [])}],
        ["最多检查 PATH 前 64 项；不执行候选文件，符号链接和同目录包装入口去重。"], "通过工具页核对 CLI 安装来源和 PATH 顺序，避免不同安装相互覆盖。")
    credential_conflict = cli.get("api_key_present") and cli.get("auth_token_present")
    invalid_cli = (cli.get("endpoint_valid") is False or cli.get("endpoint_https_or_local") is False or credential_conflict or cli.get("bedrock") and cli.get("vertex")
                   or cli.get("proxy_scheme") in ("socks5", "socks5h") or cli.get("proxy_valid") is False or cli.get("tls_verification_disabled")
                   or cli.get("extra_ca_configured") and cli.get("extra_ca_exists") is False)
    configured_cli = cli.get("custom_endpoint") or cli.get("api_key_present") or cli.get("auth_token_present") or cli.get("bedrock") or cli.get("vertex")
    add("cli_env", Status.WARN if invalid_cli else Status.PASS if configured_cli else Status.SKIPPED,
        "CLI 接口或认证环境配置需要复核" if invalid_cli else "CLI 环境配置已检查，未发现已知冲突" if configured_cli else "未设置所检查的 CLI 环境变量", [cli],
        ["只导出存在性、格式与冲突标记；不导出凭据，不验证 API 账号，未配置也可能使用本地登录。"], "核对接口协议、认证方式及云服务开关；避免混用不相容配置。")
    storage = local.get("storage", {})
    free = storage.get("free_bytes")
    add("storage", Status.UNKNOWN if not isinstance(free, int) else Status.WARN if free < 512 * 1024 ** 2 else Status.PASS,
        "资料磁盘可用空间少于 512 MiB" if isinstance(free, int) and free < 512 * 1024 ** 2 else "已检查资料所在磁盘的可用空间" if free is not None else "未取得磁盘空间", [storage],
        ["512 MiB 是提示下限，不保证大账号的事务复制、备份或更新空间足够。"], "切换或备份前留出足够空间；不自动清理任何资料。", "profile-volume-capacity")
    account = local.get("account", {})
    add("account", Status.FAIL if account.get("valid") is False else Status.WARN if account.get("pending") else Status.PASS if account.get("valid") is True else Status.UNKNOWN,
        "账号标记或目录结构不一致" if account.get("valid") is False else "发现未完成事务，副本已保留" if account.get("pending") else "已检查账号标记与事务状态" if account.get("valid") is True else "账号标记与事务状态尚未取得", [account],
        ["只检查结构和事务标记，不读取 Cookie / 登录内容，也不验证服务端会话。"], "保留 .new / .previous 和事务日志；核对副本后再恢复，不重复强制切换。")
    return result


GUIDANCE = {"http.egress": "核对代理客户端、当前网络与探测服务响应；可在工具页测试指定代理。", "http.ipv6": "结合 IPv6 配置与实际出口判断；无响应不能证明已关闭。",
            "udp.stun": "确认代理支持 UDP，或核对显式拒绝策略；超时不能判为无旁路。", "dns.leak": "本版本没有权威 DNS 收集服务，此项保留未知。",
            "network.route": "下方目标选路提供系统证据；进程级流量仍需独立验证。", "browser.webrtc": "在实际使用的浏览器重测，核对扩展与 WebRTC 策略。",
            "baseline.guard": "在持续维护预览原生进程守护；提交启动后等待新心跳，再核对指定接口 / 端口及任务归属。", "baseline.rules": "检查内核模式、运行规则顺序、目标代理组及所选节点的 UDP 能力。"}


def add_guidance(findings):
    for finding in findings:
        if finding.status in (Status.WARN, Status.FAIL, Status.UNKNOWN) and not finding.suggestion:
            finding.suggestion = GUIDANCE.get(finding.id, "")
    return findings
