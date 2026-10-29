"""Source-mapped Claude checks, with an explicit remedy and upkeep per row.

This is a product checklist, not another privacy verdict. A DNS configuration,
process name, ASN label or a successful anonymous request cannot certify a user
session or a complete traffic path.
"""
from .legacy import UPSTREAM_COMMIT, UPSTREAM_REPOSITORY
from .guide import explain_check


CHECK_PROBLEMS = {
    "proxy": ("proxy.", "cli.socks", "cli.proxy_format", "cli.bypass", "network.proxy_dns"), "tun": ("startup.tun",), "country": ("target.country", "target.region"),
    "ip_stability": (), "timezone": ("target.timezone", "clock."),
    "locale": ("target.locale",), "ipv6": ("policy.http.ipv6", "policy.browser.http_v6"),
    "dns": ("hosts.",), "webrtc": ("policy.udp.stun", "policy.browser.webrtc"),
    "guard": ("maintenance.guard",), "rules": ("maintenance.rules", "startup.rules"),
    "language": ("target.language",), "asn": (), "reachability": ("service.", "network.",),
}

# Keep the identities and order of the upstream checkdetail protocol.
ITEMS = (
    ("proxy", "代理内核", ("baseline.proxy", "extra.proxy_listener"),
     "识别所选客户端进程，并检查已配置的本机代理端口。",
     "启动已安装的代理客户端；端口不通时先测试代理。可审核原版核心的启动与修复方案。",
     "持续维护会复查进程、端口和代理层冲突；客户端更新后重新检测。", "solution"),
    ("tun", "TUN 网卡", ("baseline.tun", "extra.runtime_tun"),
     "读取接口与运行内核的 TUN 配置；不能据此认定全部流量已接管。",
     "桌面账号的启动策略需要 TUN 时，在客户端完成服务权限；原版修复可恢复其支持的 TUN 配置。",
     "持续复查接口和运行配置；代理更新或休眠唤醒后检查是否改变。", "solution"),
    ("country", "出口国家", ("baseline.country", "http.egress", "target.region"),
     "比较无认证 HTTP 探测的出口资料与用户明确填写的国家目标。",
     "按官方名单核对实际所在地及出口；中国大陆和俄罗斯不受支持。地区限制不能通过改代理、时区或账号修复。",
     "持续复查出口和目标差异；国家资料不能代替官方地区资格核验。", "settings"),
    ("ip_stability", "出口变化", ("baseline.ip_stability",),
     "使用本机私有 HMAC 比较有效出口集合；不会公开保存原始地址。",
     "发生非预期变化时检查重连、自动选路与客户端更新；变化本身不判定为账号风险。",
     "持续维护保留最近 48 小时出口变化统计；无有效观测时保留待核实。", "maintenance"),
    ("timezone", "系统时区", ("baseline.timezone", "extra.clock"),
     "读取系统时区；另用 HTTPS 响应时间检查明显的时钟偏差。",
     "时钟偏差通过系统时间同步处理；仅在自己设置了目标时区时比较差异。",
     "可在持续维护批准时区基线；漂移后按现有权限恢复，权限不足转为手动处理。", "settings"),
    ("locale", "地区格式", ("baseline.locale",),
     "读取系统地区格式，与明确设置的目标比较。",
     "按实际需要调整系统地区格式或比较目标。使用中文不自动视为故障。",
     "持续维护记录与目标的差异；变更目标后重新建立维护方案。", "settings"),
    ("ipv6", "IPv6 路径", ("baseline.ipv6", "http.ipv6", "browser.http_v6"),
     "区分接口配置、实际 IPv6 HTTP 出口与浏览器观测；没有响应不等于已经关闭。",
     "确认网络是否需要 IPv6；需要限制时在客户端正确接管，或审核原版核心的 IPv6 修改影响。",
     "持续复查原生 IPv6 及显式允许网段；浏览器 IPv6 需要页面复检。", "settings"),
    ("dns", "DNS 解析", ("dns.leak", "baseline.dns", "extra.dns_resolution", "extra.hosts"),
     "读取 DNS 配置、目标解析和 hosts 覆盖；尚无权威侧解析源观测。",
     "核对 hosts 覆盖与客户端 DNS / TUN 设置；修正解析失败后复检。只读到 Fake-IP 不代表无 DNS 泄漏。",
     "持续检查解析失败、hosts 覆盖与配置变化；权威 DNS 出口仍单独标为未核实。", "proxy-test"),
    ("webrtc", "UDP 与 WebRTC", ("baseline.webrtc", "udp.stun", "browser.webrtc"),
     "原生 UDP STUN 与当前页面 ICE 分别测量，并按地址族和显式策略比较。",
     "需要限制浏览器 UDP 时配置客户端规则与浏览器策略；超出允许范围后先纠正实际路由，再复检两种探测。",
     "后台只复检原生 UDP；浏览器更新后和使用前在此页面重新检测 ICE。", "proxy-test"),
    ("guard", "进程守护", ("baseline.guard",),
     "查询原版守护任务是否已注册、启用且正在运行。",
     "可审核并安装或修复随附开源项目的进程守护；后台只读巡检与进程急停是不同功能。",
     "持续复查原版守护状态；进程轮询存在时间窗口，不能替代防火墙。", "solution"),
    ("rules", "目标路由规则", ("baseline.rules",),
     "读取运行内核，核对 13 个域名、3 个 STUN 端口、顺序、策略组及节点 UDP 能力。",
     "填写实际代理组，选择支持所需协议的节点；规则缺失可审核原版核心修复，随后复查运行内核。",
     "持续复查运行规则，订阅或客户端更新后复检；静态文件中的规则不算生效。", "solution"),
    ("language", "客户端语言", ("baseline.language",),
     "仅客户端专用偏好能够验证客户端语言；系统语言不能替代应用实际语言。",
     "仅在有实际语言需求时调整 Claude 偏好。没有读取到专用设置时，保持未核实。",
     "持续复查可读到的应用偏好；不会为获得通过而自动改为英语。", "settings"),
    ("asn", "ASN 归属资料", ("baseline.asn",),
     "展示网络归属组织资料；不根据机构名称推断住宅属性或账号风险。",
     "资料仅供核对，无需为了 ASN 名称修改系统、购买节点或删除账号资料。",
     "持续保存脱敏观测，归属资料变化时可追溯；不作为登录放行凭据。", "maintenance"),
    ("reachability", "Claude 服务连接", ("baseline.reachability", "extra.tls", "extra.timing"),
     "分开检查网页与 API 的 DNS、TCP、TLS、HTTP 状态及耗时；不发送账号密钥。",
     "按连接阶段修复；API 匿名 401 无需修复，407 处理代理认证，429 停止密集重试，5xx 核对服务状态。",
     "持续复查原生连接并记录状态变化；登录及订阅权限须在官方客户端中确认。", "proxy-test"),
)


def checklist(report, preferences=None):
    preferences = preferences or {}
    by_id = {f["id"]: f for f in report.get("findings", [])}
    problems = report.get("diagnosis", {}).get("problems", [])
    rows = []
    for index, (key, title, ids, measurement, remedy, upkeep, action) in enumerate(ITEMS, 1):
        observed = [by_id[f] for f in ids if f in by_id]
        primary = by_id.get(ids[0], {})
        status = primary.get("status", "unknown")
        scope = primary.get("scope", "not-measured")
        summary = primary.get("summary", "本次尚未取得该项的有效观测。")
        target = {"country": "country", "timezone": "timezone", "locale": "locale", "language": "language" if preferences.get('environment_confirmed') else "locale"}.get(key)
        if target and not preferences.get(target):
            status, summary = "not_configured", "未设置比较目标；当前观测仅供核对。"
        if key == "asn" and primary.get("status") == "pass":
            status = "info"
        related = [p["id"] for p in problems if any(p["id"].startswith(prefix) for prefix in CHECK_PROBLEMS[key])]
        if report.get('environment'):
            note = next((r for r in report['assessment']['items'] if r['id'] == ids[0]), {})
            if note.get('state') in ('not_applicable', 'informational'):
                status, summary = 'info', note['reason']
        if key == 'country' and by_id.get('target.region', {}).get('status') in ('fail', 'warn', 'unknown'):
            status, summary = by_id['target.region']['status'], by_id['target.region']['summary']
        rows.append({"id": key, "number": index, "title": title, "status": status,
                     "summary": summary, "scope": scope, "measurement": measurement,
                     "observations": [{"id": f["id"], "title": f["title"], "status": f["status"], "summary": f["summary"]} for f in observed],
                     "remedy": remedy, "upkeep": upkeep, "action": action, "problem_ids": related,
                     "explanation": explain_check(key, status, bool(related)),
                     "source": UPSTREAM_REPOSITORY + "/blob/" + UPSTREAM_COMMIT + "/core/claude-switch.sh#L770",
                     "implementation": "https://github.com/qudadd/envscope"})
    return {"source_revision": UPSTREAM_COMMIT, "items": rows,
            "counts": {s: sum(r["status"] == s for r in rows) for s in ("pass", "fail", "warn", "unknown", "skipped", "info", "not_configured")},
            "boundary": "14 项逐项核对；每项只覆盖所列观测，不代表 14 项通过或账号已获授权。"}
