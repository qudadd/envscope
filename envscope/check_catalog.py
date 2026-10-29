"""The complete user-facing index exists before any measurements are made."""
from .claude_checks import ITEMS
from .extended import CHECKS
from .guide import EXPLANATIONS


EXTRA_HELP = {
    "ecosystem": ("Claude 相关外围端点能否回应", "匿名检查所列固定端点的 HTTPS 连接，不访问账号或发送密钥。", "按具体端点错误核对网络；403/404 回应不代表该服务功能可用。可在检测偏好中关闭此补充检查。"),
    "dns_resolution": ("网站名字能否解析", "把 Claude 网页和 API 的名字转换为连接地址。", "解析失败时检查网络、客户端 DNS 和 hosts；不代表已测到 DNS 出口。"),
    "target_route": ("系统准备从哪里连接", "查看目标地址使用的系统接口，不代表 Claude 进程的实际流量。", "按使用的系统代理或 TUN 模式核对；物理接口不一定代表应用绕过代理。"),
    "hosts": ("有没有本地地址覆盖", "检查 hosts 是否改变 Claude 网页与 API 的解析。", "有意设置的覆盖可保留；修改前备份文件，再复检。"),
    "proxy_layers": ("不同位置的连接设置是否一致", "比较系统与环境变量中的代理配置。", "不同应用可能使用不同配置，先测试所选连接再处理差异。"),
    "proxy_bypass": ("Claude 是否被列为直连", "查看代理绕过名单是否包含目标域名。", "确认是否有意直连；Code 配置可在首页预览修复。"),
    "proxy_listener": ("本机连接端口是否回应", "测试已发现的本机代理端口，不扫描未知端口。", "打开已有客户端并核对 HTTP 或 mixed 端口，再到工具页测试连接。"),
    "runtime_tun": ("连接内核的 TUN 是否开启", "读取兼容内核正在运行的配置。", "需要 TUN 时检查服务权限和开关；接口不可读时保留未核实。"),
    "controller_bind": ("连接控制接口是否暴露", "核对兼容内核的控制接口监听配置。", "检查是否只监听本机，以及客户端自己的认证设置。"),
    "tls": ("安全连接能否校验证书", "区分 TLS 握手、证书验证和 HTTP 回应。", "核对时间和组织证书，保留证书校验；不要关闭验证来获得通过。"),
    "timing": ("连接主要慢在哪一步", "记录探测的解析、连接和响应耗时。", "结合多次历史判断，单次耗时不能证明长期稳定。"),
    "clock": ("电脑时间是否明显不准", "用 HTTPS 响应时间估计明显的系统时钟偏差。", "偏差明显时启用系统自动校时，再重新检测。"),
    "desktop": ("是否找到 Claude 桌面版", "读取已知安装位置或系统安装记录。", "未找到时核对官方下载和安装；Code 用户可在使用范围选择 Code。"),
    "profile": ("桌面资料目录是否正常", "检查已知资料目录的可读性和结构，不验证登录。", "刚安装可能尚未创建资料；已使用但异常时先保留原资料。"),
    "config": ("配置文件能否正常读取", "检查桌面和 Code 配置的格式及安全的结构信息。", "首页可预览确定的多余逗号修复；其他格式问题先备份再编辑。"),
    "cli_paths": ("Code 是否有多个命令入口", "列出 PATH 中已知入口，提示可能的冲突。", "在常用终端运行 claude doctor 核对；本工具不自动运行发现的程序。"),
    "cli_env": ("Code 的连接和认证方式如何配置", "核对相关字段是否配置，不读取或验证密钥值。", "自定义接口和云平台按其官方方式确认；修改后重开实际会话。"),
    "storage": ("资料所在磁盘是否有空间", "检查配置和账号资料所在磁盘的可用空间。", "空间不足时通过系统存储设置清理，再复检；不自动删除账号资料。"),
    "account": ("账号存档是否等待恢复", "检查当前槽位、资料目录和未完成交换记录。", "存在待恢复副本时停止切换并保留全部资料；普通登录仍在 Claude 内完成。"),
}


def check_catalog():
    rows = [{'id':'target.region','group':'target','title':'Claude 官方地区支持','label':'实际地区与出口是否在官方支持名单内',
             'why':'分别核对用户申报的实际所在地和检测到的出口。中国大陆、俄罗斯不在名单中；时区和语言不证明所在地。',
             'next_step':'核对真实所在地及官方说明。地区条件不能通过自动配置、改时区或换账号修复。',
             'upkeep':'实际所在地、网络或官方支持名单变化后重新检查；名单核对日期为 2026-10-28。'}]
    for key, title, ids, measurement, remedy, upkeep, action in ITEMS:
        label, _, why, next_step = EXPLANATIONS[key]
        rows.append({"id": "baseline." + key, "group": "baseline", "title": title,
                     "label": label, "why": why, "measurement": measurement,
                     "next_step": next_step, "upkeep": upkeep})
    for key, title in CHECKS:
        label, why, next_step = EXTRA_HELP[key]
        rows.append({"id": "extra." + key, "group": "extra", "title": title,
                     "label": label, "why": why, "next_step": next_step,
                     "upkeep": "更改相关设置或更新软件后重新检测；持续维护可记录原生检查的变化。"})
    rows.extend([
        {'id':'device.environment','group':'measurement','title':'设备与显示环境','label':'设备资料能读取哪些',
         'why':'读取图形、显示、字体数量和虚拟化线索，不推断封禁风险。','next_step':'工具页可单独读取；遇到图形问题时核对驱动。','upkeep':'系统或驱动升级后重新采集。'},
        {'id':'browser.environment','group':'measurement','title':'当前浏览器环境资料','label':'当前窗口向网页提供哪些信息',
         'why':'记录时区、语言、屏幕和可取得的图形资料；不代表其他浏览器或 Claude 桌面版。','next_step':'在实际浏览器复查；受限字段不判为故障。','upkeep':'浏览器更新或使用方式变化后复查。'}
    ])
    from .inspection import TARGETS, MEASUREMENTS
    known = {r['id'] for r in rows}
    for key, (title, _) in TARGETS.items():
        if key not in known:
            rows.append({'id': key, 'group': 'target', 'title': title, 'label': title,
                         'why': '按已经确认的用途与连接方式检查；自动包含需要的依赖测量。',
                         'next_step': '按本次证据处理；必要条件未测量时，环境不能判为合格。',
                         'upkeep': '用途、连接或配置改变后重新检测；持续维护记录差异，不自动修改检测目标。'})
    for row in rows:
        if row['id'] == 'target.wireguard':
            row.update(why='核对指定 Windows WireGuard 隧道服务、所属进程和程序文件，再独立检查对应网卡与目标选路。',
                       next_step='服务未激活时在 WireGuard 中激活；多个隧道时在目标设置选择。权限拒绝、其他 VPN 在线或程序同名都不会通过。',
                       upkeep='守护固定隧道、程序路径与摘要；服务离线或程序改变时停止已批准的 Claude 桌面进程并记录原因，VPN 程序更新后重新审核。')
    for key, title in MEASUREMENTS.items():
        rows.append({'id': key, 'group': 'measurement', 'title': title, 'label': title,
                     'why': '独立保留本次测量来源和适用范围。',
                     'next_step': '查看本项证据与限制，按实际连接工具处理后复检。',
                     'upkeep': '网络或使用方式变化后重新测量；浏览器证据需在当前窗口重新取得。'})
    return rows
