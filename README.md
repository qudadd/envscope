# EnvScope

面向 Windows 和 macOS 的极简桌面环境工具。以 [claude-switcher](https://github.com/YOURSJEYO/claude-switcher) 为功能底座，保留原版维护能力，增加独立检测、事务式账号管理、代理诊断和历史对比。

当前代码 **0.19.0 Alpha** 新增 Windows WireGuard 专项模式：选择具体隧道，分别核对服务、所属进程、程序摘要、对应网卡与实际目标选路；原生守护固定同一服务基线。服务停止、读取权限拒绝及其他 VPN 选路分别显示原因和处理步骤。参见 [WireGuard 检测与守护](docs/WIREGUARD.md)。公开安装包以 Releases 为准。

**0.18.0 已加入**原生客户端启动 / 重开、Clash Verge TUN 持久化修复，以及 macOS Claude 专用语言设置与恢复。先正常退出 Claude，审核所选程序与改动；备份、读回、失败恢复和中断恢复都有入口。一键流程先修复客户端并自动复检，再使用实际测到的网卡预览后续守护，减少手动选择。参见 [客户端与应用语言修复](docs/CLIENT_REPAIR.md)。

**0.17.0 已加入** Windows / macOS 原生网络修复：按已确认目标勾选或全选 IPv6 接口、预览影响、申请本次系统授权、独立读回、失败回滚和中断恢复；DNS 缓存刷新单独说明不可撤销。接入一键流程与“全部检查”的所选修复，完成后自动复检并刷新接口。参见 [网络设置与恢复](docs/SYSTEM_NETWORK.md)。

**0.16.0 已加入** macOS 原生系统时区守护：审核一次后申请系统授权，每 60 秒检查批准时区；接入“保持本次设置”、地区修改、失败回滚和跨重启撤销。辅助程序和基线由 root 持有，后台不会弹出授权框。参见 [系统时区守护](docs/TIMEZONE_SERVICE.md)。

**0.15.0 已加入** macOS 原生加密 DMG 兼容：账号页直接选择原版 A–D 备份、只读挂载、文件回读校验与未完成暂存清理；无需安装旧维护核心。Windows / macOS 仍使用 .envsnap 进行跨平台认证加密备份。参见 [加密备份的格式与恢复范围](docs/DMG_ARCHIVES.md)。

**0.14.0 已加入** Clash Verge 原生路由修复：预览 16 条规则、保留用户脚本、备份与重载、实际运行验证、失败回滚和重启后恢复；接入逐项修复与持续维护。参见 [原生路由配置](docs/ROUTING.md)。

**0.13.0 已加入**原生 10 秒进程守护；先审核再启用，监测失败时停止已识别的当前用户 Claude 桌面并留痕。完整功能升级仍在进行，参见 [完整核对表](docs/FULL_PARITY_AUDIT.md) 和 [进程守护](docs/PROCESS_GUARD.md)。

账号按独立本地数据卷完整封存和载入，保留目录内已有身份与会话；新增正常退出、APFS 写时复制、内容读回及中断恢复入口。恢复前审核，所有现场副本保留。真实客户端认证、钥匙串及服务端设备判断的边界见 [账号数据卷](docs/ACCOUNT_VOLUMES.md)。

**0.12.0 已加入**：读取出口 IP 后只显示相应国家的城市，并匹配目标时区、语言与地区格式。Watchdog 可周期检查批准基线、恢复漂移、重开所选离线代理客户端并读回复检；权限不足或不能自动处理时标红。完整事件按日保存，账号切换保留独立资料、限制跨账号文件混合。仍支持全选、单项检测与批量修复。实际所在地与出口分开核对，CN / RU 官方地区条件不合格不能通过配置修改消除。[IP 联动、守护与账号隔离](docs/WATCHDOG_AND_IDENTITIES.md) · [功能与验收范围](docs/ENVIRONMENT_COVERAGE.md)。

首页贯通检测、配置与修复、复检、打开 Claude 和长期保持。桌面打开与正常重开都先重新检测，核对安装、配置、账号恢复及目标连接；未通过时保留资料并说明原因。Code 可主动完善本机连接与证书校验设置。[交付范围与验收依据](docs/PRODUCT_ACCEPTANCE.md)。

连接诊断与完整隐私验证分别报告：API 未认证探测返回 401 不会被当成密钥失效；本版未实现权威 DNS 出口、目标进程全流量关联和防火墙断网保护，不会因为网页有响应就声称零泄漏。

Scrapling 仅用于开发前期抓取和核对方案、项目与文档，不属于产品、运行依赖或检测引擎。

![EnvScope 桌面界面，离线演示](docs/images/desktop.png)

界面采用黑白配色和固定导航；问题、处理入口与复检结果直接展示。截图来自离线配置修复演示，未运行真实网络检测。设计约定见 [桌面界面](docs/UI_DESIGN.md)。

## 一键检测

Windows 桌面包解压后双击 `EnvScope.exe`。macOS 桌面包的入口为 `EnvScope.app`。程序打开独立窗口，不需要另外启动浏览器或 Python：

[下载 Windows / macOS 桌面包](https://github.com/qudadd/envscope/releases)。macOS 分 Apple Silicon 与 Intel，按处理器选择。Alpha 包未获商业代码签名 / Apple 公证。

1. 首次打开跟着教学选择使用方式；打开平时使用的连接工具，点“一键检测与修复”。
2. 检测后自动生成统一方案；“环境设置”可选择使用范围、是否完善 Code 连接，以及自动或指定本机 HTTP 代理。
3. 审核具体影响，点“确认配置并修复”。写入前再次验证所选代理，失败不写入，也不回退直连。
   需要启动 / 修复代理时，先完成这一阶段并自动复检；后续路由、网卡和守护改动会按新结果重新预览，不能提前猜测尚未出现的接口。
4. 自动复检区分已确认消除、仍存在、本次无法核实和新问题。桌面用户可点“复检后打开桌面版”；配置改变后保存工作，再点“保存后复检并重开”。未确认正常退出时不会强制终止。
5. 在自己的 Claude 登录并发一条消息；Code 用户重开常用终端或会话。手动确认收到回复不会改变技术检测结论。仍不能用时，按实际现象获取步骤。
6. 连接正常后，在首页“保持本次设置”预览并启用周期复检；可选保持已验证 Code 配置，同页可停用。独立维护页继续保留。

配置完善优先测试 Code 已有的本机 HTTP 代理，再测试已发现的候选；明确指定地址时不试用其他连接。自定义接口、Bedrock / Vertex / Foundry 和未明确更换的远程代理保留其原路径。只改用户配置文件；项目与组织设置可能覆盖它，实际会话仍需重开确认。完全相同的设置不会仅为排版而重写。复检单列配置文件凭据，不把写入成功或账号手动确认当作隐私通过。

“看懂 14 项检查”和完整技术记录按需展开，不要求先理解术语。工具页明确区分随附的 claude-switcher、Mihomo 本机接口，以及可选外部客户端 Clash Verge Rev 的作用；读取与审核后的修改分开，不会自动安装代理或提供节点。见 [新用户使用说明](docs/USER_GUIDE.md)。

检测不需要终端或手动导入。桌面包自带 Python 运行时；Windows 使用系统 WebView2，macOS 使用 WKWebView。关闭窗口后默认驻留托盘／菜单栏，从相应菜单可以重新打开或退出。在“设置 → 软件与后台”关闭驻留后，关闭窗口即退出。首次安装维护核心与系统修复可能请求管理员授权；普通读取被拒绝时，只为对应项目提供权限处理入口。

软件默认每日向 GitHub 查询版本，不下载或执行更新。用户确认后，从 `qudadd/envscope` 下载对应架构软件包，同时核对发布校验表与 GitHub SHA256，安装到用户目录中的新版本文件夹，保留旧文件。重启由用户确认；已保存的前一版本可回退。参考开源项目的更新只提示差异，经兼容测试后随 EnvScope 发布，不直接替换正在运行的核心。系统定时巡检独立于窗口驻留；其现有任务继续使用已批准的程序路径，可在维护页重新预览启用来迁移。

Windows 独立程序已在本机构建并通过隔离的真实窗口、托盘和退出测试。Windows、macOS 两种架构由发布 CI 构建并测试，结果以本标签的 Actions 为准；真实账号登录、平台授权弹窗与 Safari 外部浏览器仍需实际设备验收。手机端暂不适配。

## 功能范围

| 功能 | Windows | macOS |
|---|---|---|
| 原版 14 类检查与独立测量证据 | 原生实现 | 原生实现 |
| 18 项扩展检查、问题归因、处理步骤与复检比较 | 原生实现 | 原生实现 |
| JSON 多余逗号修复、Code 代理 / 绕过项与恢复 TLS 校验 | 预览后确认执行，备份及撤销 | 预览后确认执行，备份及撤销 |
| 所选接口 IPv6、DNS 缓存刷新、事务记录与恢复 | 原生 UAC 事务；不执行可改写脚本 | 原生 SystemConfiguration 辅助程序；保留手动地址 |
| 所选客户端启动 / 正常重开、TUN 偏好备份 / 验证 / 恢复 | Clash Verge、Mihomo Party、Clash Nyanpasu；持久化 TUN 支持 Clash Verge | 另外识别 Shadowrocket、ClashX、Surge；持久化 TUN 支持 Clash Verge，其他客户端在其界面设置 |
| Claude 专用语言、缺省 / ByHost 原值和中断恢复 | 标红并提供手动确认步骤 | 原生当前用户应用偏好；不改全局语言，实际界面另行确认 |
| 配置编辑器、系统设置和官方服务入口 | 固定目标 | 固定目标 |
| 14 项逐项检测 / 解决 / 保持清单及固定版本来源 | 原生实现 | 原生实现 |
| 用户可启停的 5 / 15 / 60 分钟原生巡检、事件与 48 小时出口变化 | 用户计划任务 | 用户 LaunchAgent |
| 批准的 Code 配置漂移恢复、私有备份、次数上限、跨重启撤销 | 原生实现 | 原生实现 |
| 已批准的系统时区守护、基线联动、更新 / 撤销 / 中断恢复 | 用户权限任务，权限不足转手动 | 原生 root 服务，前台单次申请系统授权 |
| 系统 HTTP / IPv4 / IPv6、UDP STUN、浏览器 HTTP / ICE 自动合并 | 支持 | 支持 |
| 动态账号槽位、命名、首次归档、切换前重检、复制校验与失败回滚 | 原生实现 | 原生实现 |
| 首页复检后打开桌面版、确认正常退出再复检重开 | 原生实现，同账号操作锁 | 原生实现，同账号操作锁 |
| 安装、修复、守护任务、路由迁移及维护核心更新 | 适配原版核心 | 适配原版核心 |
| 城市目标、系统时区与地区格式配置、读回与撤销 | 原生实现 | 原生实现，联动已授权时区守护 |
| 切换原版代理客户端 | 原版未提供相应命令 | 适配原版核心 |
| .envsnap 加密存档、临时浏览器 | 原生实现 | 原生实现 |
| 原版加密 DMG 导入 / 导出 | 原版未提供 | 原生格式兼容 |
| 非活动槽位的未加密目录备份 / 空槽位导入 | 原生实现 | 原生实现 |
| 代理自动发现、指定代理连接诊断、耗时与响应分类 | 原生实现 | 原生实现 |
| 最近 50 次脱敏历史、状态差异与出口集合变化提示 | 原生实现 | 原生实现 |
| CLI 安装信息、设备信息、浏览器 Canvas / WebGL 信息 | Windows 只读安装位置和硬件 / 字体信息 | 原版详细 CLI / 设备信息；原生浏览器信息 |
| 脱敏诊断包、允许网段、目标偏好与偏好恢复 | 原生实现 | 原生实现 |

14 类包括代理客户端、TUN、出口国家、出口变化、时区、地区格式、IPv6、DNS 配置、UDP / WebRTC、守护任务、代理规则、客户端语言、ASN 和服务连接。取得配置信息与验证实际流量是不同范围，详细证据单独展示。

18 项扩展检查包括：

| 分组 | 具体检查 |
|---|---|
| 域名与路径 | 两个目标的系统域名解析、按地址族查询系统选路、hosts 覆盖 |
| 代理 | 当前用户系统代理与环境变量差异、绕过名单、本机已配置端口的 TCP 监听、内核 TUN 配置、控制接口监听范围 |
| 连接质量 | TLS 证书校验、DNS / TCP / TLS / 首字节 / 总耗时、多个 HTTPS 日期与系统时间的偏差 |
| 客户端 | 常见位置 / 已注册桌面安装、资料目录、客户端 / CLI JSON 与 MCP 数量 |
| CLI 与资料 | PATH 候选入口冲突、认证和接口环境配置、资料磁盘空间、账号标记和未完成事务 |

不执行 PAC/WPAD 脚本，不扫描端口，不执行 PATH 中发现的 CLI，不读取 Cookie 或登录数据库。配置检查仅提取白名单元数据，不执行 MCP 命令，不导出密钥和 MCP 参数；经确认的配置修复会在本机读取及备份完整原文。TCP 端口接受连接不等于代理协议正常；系统选路不等于进程数据包证明；HTTP 日期比较不替代可信 NTP。

## 一站式处理

区分代理解析、目标解析、TCP、TLS / CA、代理认证 407、服务拒绝 403、限流 429、服务端错误、分段耗时、配置语法、Code SOCKS 不兼容、认证 / 云提供方冲突、账号事务和磁盘空间。TUN 未启用、语言地区差异和缺少可选文件不会被一概当成故障。具体来源和验收规则见 [从检测到处理](docs/DIAGNOSIS.md)。

自动处理覆盖确定的 JSON 多余逗号、先测试成功的本机 HTTP(S) 代理写入 Code、匹配目标的绕过项、Code TLS 校验，以及已确认的地区 / 路由 / IPv6 接口与 DNS 缓存操作。修改前列出范围并保留恢复记录；缓存内容不能撤销。未知语法、认证方式和企业 CA 提供具体入口和步骤。部分代理客户端修复仍使用明确安装的兼容核心；安装器打开后仍需继续复检。

只修改固定的桌面配置和 `~/.claude/settings.json`，保留其他键、MCP 和凭据。原文备份及恢复记录保存在 `~/.envscope/config-backups`，**未加密、可能含密钥，不可分享**。权限保护也取决于用户目录 ACL。逐文件原子替换；多文件或维护步骤可能部分完成，会明确报告并保留备份。撤销支持跨重启哈希校验；文件后来又被修改时拒绝覆盖，需要按备份手动合并。

方案绑定当前本机报告且有有效期；历史 / 导入报告不能授权修复。复检没有取得证据时显示“无法核实”，不计为已解决。服务端权限、额度、组织认证和服务故障提供对应官方入口，不能通过本机改配置保证解决。

原版完整源码锁定在 `870c4ca`，57 个文件逐一校验并随产品分发。工具页使用固定操作适配原版的独立安装；未安装、平台不支持或版本缺少命令时会明确禁用。安装器打开只代表安装流程已开始，不能作为安装完成的证据。原版输出不会变成 EnvScope 的独立检测通过结果。详见 [逐项功能对照](docs/FEATURE_PARITY.md)。

## 持续维护

“持续维护”页先预览再启用用户计划任务 / LaunchAgent，默认只读巡检。可选保持已批准的 Code 五个字段、时区和地区格式，以及已验证本机代理的节点与客户端。至少间隔 5 分钟、每项 24 小时最多尝试 3 次，反复漂移会暂停。后台不提权、不安装程序、不停止 Claude、不切换账号、不回退直连；macOS 时区权限不足转手动，特权守护仍需另行安装原版。完整事件按日追加，停用后保留。

可立即复检、查看最近报告、事件、48 小时出口变化和停用。退出页面不停止已启用的任务；停止按钮先关闭恢复标记，再移除自己的任务。注册、等待执行、完成、超期、失败与恢复受阻分别显示。Windows 与两种架构的 macOS 包增加真实 OS 调度验收：注册、两次自动执行冻结 worker、移除；结果见对应标签的 Actions。该验收不联网、不修改用户配置，不能代替权限、重新登录、休眠恢复或真实账号验收。详见 [逐项检测与长期保持](docs/CLAUDE_CHECKS.md)。

## 账号与维护

“账号”页支持 A-D 及自定义槽位。切换前重新运行原生检测，拒绝过期、缺失或失败的必需证据；确认应用退出后，先创建并校验暂存副本，再提交交换。异常时尝试回滚；发现未完成事务会保留副本、阻止继续写入。断电后的自动恢复尚未实现。首次切换会将原有资料归入 A。

账号沿用 `~/.claude-switcher` 存档，实时资料位于 Windows `%APPDATA%/Claude` 或 macOS `~/Library/Application Support/Claude`。不要同时用原版和 EnvScope 交换账号。`keep-in-workspace.txt` 默认关闭，0.12 起仅允许显式选择的 `skills/` 文件；身份、Cookie、会话与设置禁止跨账号混合，旧清单有此类路径时停止切换并提示调整。切换事件记录在 `~/.claude-switcher/account-events`，不记录凭据内容。

账号页优先使用 **.envsnap 加密备份**：Scrypt 派生密钥、AES-256-GCM 认证加密、逐文件 SHA-256 清单；错误密码、损坏、路径异常或非空槽位均拒绝导入。密码至少 12 字符，不保存、不进入进程参数；临时明文放在受限目录，完成后清理，不声称安全擦除。存档上限 8 GiB。高级目录备份仍未加密，不可分享。macOS 原版 DMG 入口保留。复制资料不保证服务端会话、系统凭据库或跨系统登录迁移。

“工具”页列出维护操作的实际影响。安装 / 修复可能改写代理规则、IPv6、时区、地区格式和后台任务。完整卸载并不等于恢复历史网络设置。原版更新只更新已安装的维护核心；EnvScope 本体使用“设置 → 软件与后台”的校验更新。当前 Alpha 使用发布摘要校验，尚无商业代码签名 / Apple 公证。

## 从源码启动

源码运行需要 Python 3.10+，先在源码目录执行 `python -m pip install '.[desktop]'`，再在 Windows 双击 `start-windows.cmd`，或在 macOS 运行 `start-macos.command`。日常用户直接下载自带运行时的桌面包即可。Windows 10/11 和 macOS 自带的 curl 用于原生 HTTP 检测。

以下命令用于开发或进阶诊断，日常桌面使用无需执行。

## CLI

需要 Python 3.10+；在线 CLI 检测还需要系统 `curl`。浏览器页面无第三方 JavaScript/CSS 依赖。

下载本仓库源码后，在源码目录中运行：

```powershell
cd envscope
python -m envscope --help

# 默认仅采集本机只读信息，不向公共服务发探测请求
python -m envscope audit --html reports/audit.html

# HTTP + 原生 UDP STUN + IPv6；公共端点会看到探测来源地址
python -m envscope audit --online --stun --ipv6 --html reports/audit.html

# 当前浏览器的真实观测；在浏览器打开输出的 loopback 地址
python -m envscope serve
```

命令行可 `python -m pip install .` 后使用 `envscope`。源码运行独立窗口请安装 `python -m pip install '.[desktop]'`；浏览器兼容入口是 `python -m envscope desktop --browser`。Windows 和 macOS 的系统适配器读取各自的网卡、路由和 DNS 配置；配置存在不能证明流量已接管。

退出码仍按选定验证范围：`0` 范围内通过，`1` 明确策略或目标不符，`2` 证据不完整或需要复核，`3` 输入/本地资源错误。连接诊断显示“服务有响应”时，完整隐私范围仍可能返回 `2`；这是覆盖不足，不等于服务不可用。默认离线运行返回 `2`，不是程序崩溃。

## 检测规则的升级

| 观测 | EnvScope 的解释 |
|---|---|
| STUN 超时、IPv6 无响应 | 未知，不能推导“零暴露”或“已关闭 IPv6” |
| 原生 UDP 有响应 | 只说明原生 UDP 路径；与浏览器 ICE 分开 |
| HTTP 200 但 IP 响应结构无效 | 未知；验证码页面不会成为有效 IP 证据 |
| HTTP 401 / 403 / 429 / 5xx | 分别标注认证、访问拒绝、限流、服务异常 |
| UDP/ICE 与 HTTP 出口不同 | 无明确允许地址时提示复核，不直接宣称“真实 IP 泄漏” |
| 观测地址超出用户明确配置的允许 CIDR | 策略违反；不推断地址所有者或物理位置 |
| 只有 mDNS、私网或 TURN relay 候选 | 没有可比较公网候选，保留未知 |
| TUN 网卡存在、代理进程存活、Fake-IP、DoH 可达 | 配置或行为线索，不能替代实际路径验证 |
| 中文语言、时区、ASN 机构名 | 不用于推断账号安全、住宅属性或封禁概率 |
| 上游 `checkdetail` 报告中的 `ok` | 导入为“未独立重测”，不继承通过结论 |

默认 `privacy` 范围要求 IPv4、IPv6、UDP、浏览器和权威 DNS 证据。若只检查 HTTP 传输，可明确选择 `--profile transport`；此时 `0` 也只表示所选范围内通过，其他未知项仍展示。

## 配置允许地址

创建不会提交到 Git 的 `policy.private.json`。下面地址是文档示例，请替换成自己**明确知道应当使用的**出口网段；不要直接把待测结果自动学习成可信范围。

```json
{
  "allowed_ipv4": ["203.0.113.10/32"],
  "allowed_ipv6": ["2001:db8:1234::/48"]
}
```

```powershell
python -m envscope audit --online --stun --ipv6 --policy policy.private.json
```

允许列表区分 IPv4/IPv6，可配置多个合法出口。没有列表时，仅报告同一场景内的一致性或差异。CIDR 命中证明符合这份策略，不证明运营商、国家或“住宅 IP”属性。

## 指定代理和目标

```powershell
python -m envscope audit --online --proxy http://127.0.0.1:7890
# 含凭据时，从自己设置的环境变量读取，避免写进命令历史
python -m envscope audit --online --proxy-env ENVSCOPE_PROXY_URL
python -m envscope audit --online --target https://example.com/
# 可选：密钥从 ENVSCOPE_CONTROLLER_SECRET 读取，只访问 loopback GET /configs
python -m envscope audit --online --controller http://127.0.0.1:9090
```

显式代理失败不会回退为另一条路径重试。HTTP 代理设置不会自动控制原生 STUN；跨路径差异必须结合实际 TUN/UDP 策略解释。没有 `--proxy` 时，curl 使用环境代理和系统路由，**不等于 Windows 浏览器的 WinINET 代理设置**。

curl 不载入用户 `.curlrc`，不执行远端脚本，不跟随 HTTP 重定向。控制接口不经过环境代理、不跟随重定向，不导出返回配置中的密钥。

## 系统与浏览器观测

一键检测在当前浏览器收集 HTTP 与 ICE 观测，然后自动传给本机 loopback 进程，合并系统检测结果。不会传给 EnvScope 外部服务器，不需要用户交换文件。浏览器与系统各自使用对应路径的 HTTP 对照。

高级 CLI 仍接受 `--browser <原始观测文件>`，重新评估地址和 ICE 类型。过期、未来、脱敏或未完成的观测不能通过。用户提供的观测未签名，不用于可信远程审计。

浏览器不申请麦克风/摄像头权限，不保证覆盖浏览器可使用的全部接口。网页不能强制双栈域名走某一地址族；IPv6 使用专用端点，结果保持独立。

## 报告、导入与变化比较

```powershell
python -m envscope import-switcher <已保存的last-check.txt>
python -m envscope report reports/audit.json --html reports/audit.html
python -m envscope diff reports/before.json reports/after.json
```

默认导出对地址使用本报告内别名，保留证据关系，隐藏常见用户目录名，删除 URL 凭据、查询参数和已识别的密钥字段。时区、语言、软件信息等仍可能识别环境，分享前需要自行复核。`diff` 只比较检查状态，不用不同报告的地址别名推断 IP 变化。

桌面偏好、对比密钥与最近 50 次脱敏历史保存在 `~/.envscope`。原始检测地址只在本次进程内存中评估；历史用本机随机密钥的 HMAC 比较实际观测的出口集合，密钥丢失后不跨密钥声称出口变化。历史页面不能用旧报告授权启动，切换仍会重新检测。出口变化本身不等于泄漏或账号风险。

`--include-sensitive` 可在本地保留原始地址。`reports/`、`artifacts/`、`.env`、`*.private.json` 均被 Git 忽略。静态 HTML 报告不加载外部资源、不包含可执行脚本。浏览器分享版与 CLI 诊断报告是两种有明确 `kind`/`tool` 的格式，不混用。

## 开发与验证

```powershell
python -m unittest discover -s tests -v
node --test tests/browser.test.mjs
node --check envscope/web/app.mjs
node --check envscope/web/controls.mjs
node --check envscope/web/diagnosis.mjs
# 可选开发依赖，运行离线页面交互与截图检查
python -m pip install playwright
python -m playwright install chromium
python -m scripts.browser_smoke
python -m pip wheel . --no-deps --wheel-dir dist
python -m scripts.verify_package dist
```

回归测试只使用合成数据及 loopback 假服务，不断开真实网络、不使用真实账号、不发送实际 UDP 到外部 STUN 端点。规则 CI 在 Windows/Linux/macOS 运行；产品适配范围为 Windows/macOS。自动化通过不等于真实账号、维护权限和浏览器场景均已验收。运行记录见 [Actions](https://github.com/qudadd/envscope/actions)。

桌面包构建：安装开发依赖 `pyinstaller>=6.10,<7`，在目标 Windows/macOS 系统运行 `python -m scripts.build_desktop`。也可在 GitHub Actions 手动运行 `desktop packages`。桌面产物目前未签名，首次启动体验需要纳入平台验收。

macOS 打包要求 cryptography 静态链接 OpenSSL，构建脚本会检查。Intel 从源码构建加密库时，先安装 Rust、OpenSSL 开发库，按[官方说明](https://cryptography.io/en/latest/installation/#building-cryptography-on-macos)使用 `OPENSSL_STATIC=1` 并禁用旧 wheel 缓存；CI 已配置此步骤，避免与 Python 自带的 OpenSSL 冲突。最终用户不需要这些构建工具。

阅读 [逐项功能对照](docs/FEATURE_PARITY.md)、[验证记录](docs/VALIDATION.md)、[源码审查与方案取舍](docs/RESEARCH.md)、[检测架构](docs/ARCHITECTURE.md)、[实施路线](docs/ROADMAP.md)、[安全边界](SECURITY.md) 和 [第三方来源](THIRD_PARTY_NOTICES.md)。
