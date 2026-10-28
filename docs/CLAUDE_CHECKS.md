# Claude 逐项检测、解决与保持

版本 0.4，2026-10-27。以 claude-switcher 的固定版本
[`870c4ca`](https://github.com/YOURSJEYO/claude-switcher/tree/870c4ca0754234965878ef58144d7a755d965037)
为功能来源。完整 MIT 源码随包分发，不把上游输出的 `ok` 直接作为验证结果。

## 14 项对应

页面直接展示以下各行的本次观测、测量范围、处理方式和保持办法。
`envscope/claude_checks.py` 保存稳定 ID 与来源；检测由原生采集器完成。

| 项目 | 本次检测与解决方式 | 长期保持 |
|---|---|---|
| 代理内核 | 已知客户端进程、配置端口；测试指定代理；审核原版统一启动/修复方案 | 定时复查进程、端口、代理层差异 |
| TUN 网卡 | 接口、内核运行配置、目标系统选路分别展示；按实际启动策略开启或修复客户端服务 | 复查运行配置，发现关闭或接口消失保留问题 |
| 出口国家 | HTTP 出口资料与明确目标比较；修正填错的目标或核对实际连接 | 定期比较；不自动改变真实地区或宣称服务资格 |
| 出口变化 | 私有 HMAC 比较有效地址集合 | 保存 48 小时观测与变化次数，失效或换密钥不伪造变化 |
| 时区/时钟 | 系统时区比较，另测多个 HTTPS 日期偏差；指向时间设置 | 记录偏差，不自动伪装所在地或替代可信 NTP |
| 地区格式 | 读取并比较明确目标；按需要调整设置 | 复查差异；没有目标时不当成故障 |
| IPv6 | 接口配置、实际 HTTP 出口、浏览器观测分开；核对接管与显式网段策略 | 原生周期复查；浏览器侧仍需页面检测 |
| DNS | 配置、两目标解析、hosts 覆盖；按具体解析失败处理 | 复查解析及覆盖；未实现权威解析源采集，不声称无 DNS 泄漏 |
| UDP/WebRTC | 原生 STUN 和当前浏览器 ICE 分开测量 | 后台只测原生 UDP；使用前、浏览器更新后重测页面 ICE |
| 进程守护 | 查询原版任务注册、启用、运行；缺少时审核并安装/修复固定版本核心 | 定期查询原版任务；本项目只读巡检不冒充进程急停或防火墙 |
| 路由规则 | 运行内核的 13 个域名、3 端口、次序、目标与 UDP 节点；按项审核原版修复 | 持续复查实际运行规则，订阅更新后不靠静态文本判通过 |
| 客户端语言 | 只认可应用专用偏好；系统语言不代替应用语言 | 复查可读取偏好；无专用数据时保持待核实 |
| ASN | 归属资料，仅供信息核对 | 保存脱敏记录；不据组织名判住宅属性或账号安全 |
| 服务连接 | 网页/API 分别定位 DNS/TCP/TLS/HTTP 错误、代理 407、429/5xx；代理测试与配置修复 | 定期记录连接状态；登录、订阅与组织权限仍在官方客户端确认 |

针对代理、TUN、守护和规则的“审核本项处理方案”可以接入随附开源
项目的安装/修复。上游 `fix` 是统一操作，可能影响其他系统设置，必须
先展示全部影响并明确确认，不能包装成只改这一行。安装器打开后仍需复检。
其平台差异与未实现的原生能力见 [功能对照](FEATURE_PARITY.md)。

## 可持续运行的开源实现

`envscope/maintenance.py` 实现后台原生巡检与批准字段的漂移恢复；
`envscope/scheduler.py` 实现当前用户的 Windows 计划任务 / macOS LaunchAgent。
没有新增服务端依赖，也没有把 Scrapling 带进产品。

1. 先点击一键检测，生成当前报告。
2. 在“持续维护”选择 5、15 或 60 分钟，默认只读巡检。
3. 如果选择配置保持，先校验 Code 配置及无凭据的本机 HTTP(S) 代理。
4. 展示后台行为、联网端点、字段值、备份位置、恢复上限后，明确确认启用。
5. 系统注册验证成功后才保存启用标记。未执行过、执行超期、失败、恢复暂停
   与最近一轮完成分别显示；注册本身不表示巡检成功。
6. 可立即复检、查看本轮报告及事件；停用先写关闭标记，再移除自己的任务。
   移除失败也不再执行配置恢复，保留文件供核对。

默认在当前用户登录时工作。休眠、退出登录、系统策略和权限会影响实际调度，
不承诺精确到秒。移动或删除应用目录后需重新注册方案；心跳超期会提示复核。
关闭本地界面不停止已批准的维护；页面会提示“结束界面，维护继续”。

只保持 `~/.claude/settings.json` 的 `env` 中以下五项的批准值或未设置状态：
`HTTPS_PROXY`、`https_proxy`、`NO_PROXY`、`no_proxy`、
`NODE_TLS_REJECT_UNAUTHORIZED`。其他当前配置、MCP、凭据及新增加的设置保留。
这不覆盖项目/组织策略、启动终端的环境变量或 Claude 内部已加载的设置。

恢复前备份原文件，逐文件原子替换并复查批准字段。路径含链接/reparse、
文件删除或格式损坏、并发变更、备份失败、代理 API TLS 验证失败时不覆盖。
24 小时最多自动恢复三次，重复变化、无法核实次数时间或比较设置改变后暂停恢复。
换代理前应停用并审核新基线，避免与其他配置管理工具来回改写。

最近 100 条事件和最新原生报告存本机 `~/.envscope/maintenance`。
原文备份及恢复哈希存 `~/.envscope/config-backups`，可能含密钥，未加密、不可分享。
“工具 → 配置备份”展示最近 20 份恢复记录，重新打开后仍可使用。
撤销支持跨服务重启，必须同时验证备份及当前文件哈希；文件后来有修改会拒绝覆盖。
从维护事件撤销会先停用维护。断电后的自动事务重建仍未实现。

## 验证与来源

回归使用临时目录、合成观测、假运行器和 loopback；没有为开发机安装任务、修复
真实 Claude 配置、改变网络或切换账号。Windows XML 对照微软官方 XSD 检验三种间隔。
0.7 的冻结包 CI 另用隔离 Windows / macOS 系统，注册真实用户任务，观察两次自动执行
维护 worker 的无副作用 `--check-runtime` 入口，再移除并独立查询确认。
该步骤不运行网络巡检或恢复，不读取真实维护状态，仅验证实际调度生命周期。
脚本需 CI 标记及单独 opt-in，普通本机运行拒绝；证据随 Actions 附件保存。
当前用户权限、重新登录、休眠恢复和真实网络巡检仍需分别验证。

- [上游 14 项实现](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/core/claude-switch.sh#L770)
- [上游配置看门狗](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/daemons/tz-watchdog.sh)
- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)
- [Claude Code 设置](https://code.claude.com/docs/en/settings)
- [微软 Task Scheduler Schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema)
- [微软任务权限上下文](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
- [Windows 账号名到 SID 的身份解析](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.ntaccount.translate)
- [Apple 创建 launchd 任务](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

来源经 Scrapling 核对，原文摘要与哈希元数据记入 `sources.lock.json`；
官方文档不是新加入的运行库，不复制其他许可证下的守护代码。
