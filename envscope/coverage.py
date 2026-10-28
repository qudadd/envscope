"""Traceable capability parity and environment coverage, never a risk score."""
UPSTREAM = 'https://github.com/YOURSJEYO/claude-switcher'
REVIEWED_COMMIT = '495b9952f36b8b7b7575fa0d8de48c2465dbf486'

FEATURES = (
    ('audit','14 项基础与逐项报告','native','checks','原始证据、问题说明、复检；另有 18 项扩展与目标验收。'),
    ('status','账号状态与命名','native','accounts','本机槽位与存档状态，不是服务端账号验证。'),
    ('switch','账号切换与启动检查','native','accounts','新检查、独占事务、校验复制、恢复记录；不使用旧 Windows 覆盖路径。'),
    ('keep','跨账号保留指定文件','native','accounts','兼容 keep-in-workspace.txt；只保留用户指定的通用设置。'),
    ('fix','系统环境与路由修复','fix','tools','使用已安装原版核心；先展示影响并确认，随后独立复检。'),
    ('code','Code 配置修复与撤销','native','audit','备份、字段预览、写入、自动复检与可验证撤销。'),
    ('region','地区与时区目标','native','audit','地区资格单独验证；时区 / 语言不是所在地或风控结论。'),
    ('set-region','原版系统地区设置','set-region','tools','macOS 原版操作；需要确认实际地区合格。Windows 原版无此命令。'),
    ('client','代理客户端选择','native','settings','原生检测目标；macOS 原版核心可另执行 set-client。'),
    ('fingerprint','设备、显示与虚拟化资料','native','tools','Windows / macOS 原生只读采集，不根据中文字体或虚拟机推断封禁风险。'),
    ('cli-info','CLI 安装与多入口检查','native','tools','只读路径、包元数据与配置体积；未知版本不执行任意发现的程序。'),
    ('browser','临时浏览器','browser','tools','独立资料、不继承扩展或 Cookie，限制非代理 UDP；不等于防火墙隔离。'),
    ('snapshot','加密存档导出与导入','native','accounts','两平台 AES-256-GCM 加密、认证、清单验证；只导出非活动槽位、导入空槽位。'),
    ('dmg','原版加密 DMG 兼容','snapshot-export','tools','保留 macOS 原版导入 / 导出，不把 .envsnap 当作 DMG。'),
    ('proxy','明确代理连接诊断','native','tools','HTTP / HTTPS / SOCKS5 传输验证；匿名 401 不等于登录成功。'),
    ('guard','代理故障进程守护','install','tools','随原版维护核心安装；10 秒轮询存在间隙，不能称为防火墙 Kill Switch。'),
    ('watchdog','系统时区看门狗','mac-install','tools','macOS 原版独立服务；Windows 原版不提供。与 Code 字段保持区分。'),
    ('routing','域名与 UDP 路由维护','fix','tools','保留原版 13 类域名及 STUN 规则入口；实际路线需要复检。'),
    ('upkeep','持续检查与配置保持','native','upkeep','用户任务 / LaunchAgent；仅恢复明确批准的 Code 字段，保留备份。'),
    ('tray','托盘 / 菜单栏常驻','native','settings','独立桌面包可驻留、隐藏、唤回；浏览器模式不具备系统托盘。'),
    ('update','完整软件与上游更新','native','settings','EnvScope 完整包校验、重启、回滚；原版核心更新在工具页另列。'),
    ('install','原版安装 / 卸载入口','install','tools','固定校验的安装器，授权窗口由用户完成；Windows 原版卸载仍按说明执行。'),
    ('history','历史、出口变化与诊断导出','native','history','本机脱敏历史；48 小时出口变化不是服务端风险评分。'),
)


def feature_catalog(legacy, browser):
    actions = {a['id']:a for a in legacy.get('actions', [])}
    rows = []
    for key,title,adapter,page,note in FEATURES:
        if adapter == 'native':
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
    ('guard','07 / 后台保护',('baseline.proxy','baseline.tun','baseline.guard','extra.runtime_tun','extra.controller_bind'), '是否启动、是否配置、是否取得实际流量证据分别展示；进程轮询不是防火墙隔离。'),
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
