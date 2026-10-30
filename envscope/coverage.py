"""Traceable capability parity and environment coverage, never a risk score."""
UPSTREAM = 'https://github.com/YOURSJEYO/claude-switcher'
REVIEWED_COMMIT = '92cd62f95f98599215995406deaa7edd89c97c40'

FEATURES = (
    ('audit','14 项基础与逐项报告','native','checks','原始证据、问题说明、复检；另有 19 项扩展与目标验收。'),
    ('status','账号状态与命名','native','accounts','本机槽位与存档状态，不是服务端账号验证。'),
    ('switch','账号切换与启动检查','native','accounts','新检查、独占事务、校验复制、恢复记录；不使用旧 Windows 覆盖路径。'),
    ('keep','跨账号保留技能文件','native','accounts','keep-in-workspace.txt 仅允许 skills/；身份、Cookie、凭据和设置禁止跨账号混合。'),
    ('fix','一键配置与修复','native','audit','按当前检测依次生成客户端 / TUN、网络、地区、应用语言、Code、路由与守护方案，确认后处理并复检；无法自动修复的项目给出手动步骤。'),
    ('client-repair','客户端启动与 TUN 修复','native','upkeep','所选程序正常启动 / 重开、Clash Verge TUN 偏好备份和验证；失败及中断可恢复，先复检再生成后续守护方案。'),
    ('wireguard','WireGuard 服务与隧道基线','native-win','audit','Windows 具体隧道服务、所属进程、程序摘要、对应网卡与目标选路分别核对；进程守护固定同一基线。不会读取私钥或自动更换 VPN。'),
    ('application-language','Claude 应用语言与恢复','native-mac','upkeep','Mac 只处理已确认目标的 Claude 专用语言，保留多语言、缺省与 ByHost 原值；Windows 提供手动步骤。实际界面另行确认。'),
    ('system-network','IPv6 与 DNS 缓存修复','native','upkeep','读取接口、勾选 / 全选、一次确认后申请系统授权，原配置备份、独立读回、中断恢复；缓存刷新不可撤销，连接与出口另行复检。'),
    ('code','Code 配置修复与撤销','native','audit','备份、字段预览、写入、自动复检与可验证撤销。'),
    ('region','地区与时区目标','native','audit','地区资格单独验证；时区 / 语言不是所在地或风控结论。'),
    ('set-region','系统地区配置与撤销','native','audit','Windows / macOS 原生城市目标、时区和地区格式写入、读回及撤销；同步已授权的 macOS 守护基线。'),
    ('client','代理客户端选择','native','settings','原生检测目标；macOS 原版核心可另执行 set-client。'),
    ('fingerprint','设备、显示与虚拟化资料','native','tools','Windows / macOS 原生只读采集，不根据中文字体或虚拟机推断封禁风险。'),
    ('cli-info','CLI 安装与多入口检查','native','tools','只读路径、包元数据与配置体积；未知版本不执行任意发现的程序。'),
    ('browser','临时浏览器','browser','tools','独立资料、不继承日常 Cookie、限制非代理 UDP；独立清理进程与重启恢复，使用中或无法核实则保留。不等于防火墙隔离。'),
    ('snapshot','加密存档导出与导入','native','accounts','两平台 .envsnap 与原版 Windows .csnap；加密、认证与导出逐文件回读，只导出非活动槽位、导入空槽位。.csnap 保持原 A–D 槽位。'),
    ('dmg','原版加密 DMG 兼容','native-mac','accounts','macOS 原生 A–D 导入 / 导出、只读挂载、逐文件回读与遗留暂存清理；Windows 使用 .envsnap。'),
    ('proxy','明确代理连接诊断','native','tools','HTTP / HTTPS / SOCKS5 传输验证；匿名 401 不等于登录成功。'),
    ('guard','代理故障进程守护','native','upkeep','独立用户任务每 10 秒监测指定端口或网卡 / 内核，按批准范围停止桌面进程；心跳、创建时间核对和日志，不是防火墙。'),
    ('components','旧后台任务迁移与恢复','native','upkeep','核对固定任务的命令、用户与原脚本，审核后保存定义和权限再移除登记；可整笔恢复，账号、脚本与旧界面保留。'),
    ('software-cleanup','旧软件清理与恢复','native','upkeep','单项 / 全选、预览确认、先停用旧任务，再可逆移走已识别的程序和启动入口；账号、凭据、配置保留，未知文件转手动。'),
    ('watchdog','时区与地区格式守护','native','upkeep','按批准基线恢复并读回；macOS 可前台授权原生 60 秒系统服务，支持更新、移除与恢复旧基线。Windows 权限不足时转手动。'),
    ('routing','域名与 UDP 路由维护','native','upkeep','Clash Verge 原生预览、保留脚本、16 条置顶规则、加载读回与恢复；其他客户端提供手动步骤，运行规则不等于流量证明。'),
    ('upkeep','持续检查与配置保持','native','upkeep','用户任务 / LaunchAgent；批准字段与系统基线恢复，代理离线重开所选客户端，冷却、复检及按日事件日志。'),
    ('tray','托盘 / 菜单栏常驻','native','settings','独立桌面包可驻留、隐藏、唤回；浏览器模式不具备系统托盘。'),
    ('update','完整软件与上游更新','native','settings','EnvScope 完整包校验、重启、回滚；原版核心更新在工具页另列。'),
    ('install','原版安装 / 卸载入口','install','tools','固定校验的安装器，授权窗口由用户完成；Windows 原版卸载仍按说明执行。'),
    ('history','历史、出口变化与诊断导出','native','history','本机脱敏历史；48 小时观测、不同出口集合与变化次数分别计数，只保留 HMAC 对照值，不等于不同 IP 总数或服务端风险评分。'),
    ('check-preferences','持久可选检查与诊断日志','native','settings','一键与后台共用可选检查偏好；必需依赖保留，跳过不算通过。512 KiB 双份命令日志，可关闭与清除；固定白名单 ZIP 导出。'),
)


def feature_catalog(legacy, browser):
    actions = {a['id']:a for a in legacy.get('actions', [])}
    rows = []
    for key,title,adapter,page,note in FEATURES:
        if adapter in ('native-mac', 'native-win'):
            state = 'native' if legacy.get('platform') == ('Darwin' if adapter == 'native-mac' else 'Windows') else 'not_upstream'
        elif adapter == 'native':
            state = 'native'
        elif adapter == 'browser':
            state = 'native' if browser.get('available') else 'needs_browser'
        elif adapter == 'mac-install' and legacy.get('platform') != 'Darwin':
            state = 'not_upstream'
        else:
            action = actions.get('install' if adapter == 'mac-install' else adapter, {})
            state = 'not_upstream' if not action.get('supported') else 'legacy' if legacy.get('backend',{}).get('installed') and action.get('available') else 'needs_core'
        rows.append({'id':key,'title':title,'state':state,'page':page,'note':note})
    return {'rows':rows,'upstream':UPSTREAM,'reviewed_commit':REVIEWED_COMMIT,
            'boundary':'功能对照逐项区分原生实现、维护核心依赖和原版的平台边界。保留源码不等于服务已安装或功能已通过真实账号验收。'}


DIMENSIONS = (
    ('region','01 / 地区与时间',('target.region','baseline.country','baseline.timezone','baseline.locale','extra.clock'), '按实际使用地区核对官方名单；时区、语言仅与自己设定的目标比较。'),
    ('network','02 / 连接与出口',('target.path','target.service','http.egress','http.ipv6','baseline.ip_stability','baseline.asn','extra.tls','extra.timing'), '查看各路径的独立响应、地址族、出口变化及 TLS 证据。'),
    ('dns','03 / DNS 与路由',('extra.dns_resolution','baseline.dns','extra.hosts','extra.target_route','baseline.rules','dns.leak','network.route'), '配置、解析行为与实际出口证据分开；权威 DNS 出口和目标进程全流量关联仍未实现。'),
    ('udp','04 / UDP 与浏览器',('udp.stun','browser.webrtc','browser.http_v4','browser.http_v6','baseline.ipv6'), '原生 STUN 与浏览器 ICE 分别测量；未响应不是无泄漏证明。'),
    ('device','05 / 设备与浏览器环境',('device.environment','browser.environment','baseline.language'), '显示字体数量、图形、虚拟化线索与浏览器环境；不伪造或随机化指纹。'),
    ('client','06 / 客户端与配置',('extra.desktop','extra.profile','extra.cli_paths','extra.cli_env','target.config','target.auth'), '识别安装、配置冲突、认证方式；不读取密钥，也不声称验证了订阅。'),
    ('guard','07 / 后台保护',('baseline.proxy','baseline.tun','baseline.guard','target.wireguard','target.tun_route','extra.runtime_tun','extra.controller_bind'), '是否启动、是否配置、是否取得实际流量证据分别展示；进程轮询不是防火墙隔离。'),
    ('account','08 / 账号与持续变化',('extra.account','extra.storage','baseline.ip_stability'), '本地存档完整性和历史出口变化可测；服务端画像、行为评分及封禁概率不可从本地推断。'),
)


def environment_portrait(report):
    findings = {f['id']:f for f in report.get('findings',[])}
    annotations = {v['id']:v for v in report.get('assessment',{}).get('items',[])}
    dimensions = []
    for key,title,ids,note in DIMENSIONS:
        rows = []
        for identity in ids:
            f, a = findings.get(identity), annotations.get(identity,{})
            excluded = a.get('state') == 'not_applicable' or (not f and identity.startswith('target.') and report.get('environment') and identity not in report['environment']['required'])
            status = 'not_applicable' if excluded else f['status'] if f else 'not_measured'
            rows.append({'id':identity, 'title':f['title'] if f else identity, 'status':status,
                         'required':a.get('required',False), 'summary':a.get('reason','所选用途不需要这一目标条件。') if excluded else f['summary'] if f else '本轮尚无该项证据。',
                         'next_step':a.get('next_step') or (f.get('suggestion','') if f else '完成对应检测；没有证据不计为通过。')})
        measured = sum(r['status'] in ('pass','warn','fail') for r in rows)
        problems = sum(r['status'] == 'fail' for r in rows)
        pending = sum(r['status'] in ('unknown','skipped','not_measured') for r in rows)
        dimensions.append({'id':key,'title':title,'rows':rows,'note':note,'measured':measured,'problems':problems,'pending':pending,
                           'review':sum(r['status']=='warn' for r in rows),'not_applicable':sum(r['status']=='not_applicable' for r in rows)})
    return {'dimensions':dimensions,'scope':'本轮证据分布，不是服务端风控评分。已测范围合格不等于地区资格、账号永不受限或全流量安全。',
            'unmeasurable':['服务端设备关联与行为评分','真实账号登录、订阅及模型权限','防火墙级持续断网保证'], 'created_at':report.get('created_at')}
