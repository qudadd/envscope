# EnvScope

**Claude 环境检测、修复与持续守护。**

面向 Windows 和 macOS 的开源桌面工具。确认地区与时区后，一键检查连接和配置，直接查看问题、修复办法与复检结果；需要长期保持时，再启用后台守护。

[下载](https://github.com/qudadd/envscope/releases/tag/v0.25.0-alpha.1) · [使用说明](docs/USER_GUIDE.md) · [文档目录](docs/README.md) · [反馈问题](https://github.com/qudadd/envscope/issues)

## 下载与启动

当前版本：**0.25.0 Alpha**。独立软件包自带运行环境，日常使用无需安装 Python 或输入命令。

| 系统 | 下载 | 启动方式 |
|---|---|---|
| Windows · x64 | [Windows ZIP](https://github.com/qudadd/envscope/releases/download/v0.25.0-alpha.1/EnvScope-Windows-x64.zip) | 完整解压，打开 `EnvScope.exe` |
| macOS · Apple 芯片 | [Apple Silicon ZIP](https://github.com/qudadd/envscope/releases/download/v0.25.0-alpha.1/EnvScope-macOS-arm64.zip) | 解压，打开 `EnvScope.app` |
| macOS · Intel | [Intel ZIP](https://github.com/qudadd/envscope/releases/download/v0.25.0-alpha.1/EnvScope-macOS-x64.zip) | 解压，打开 `EnvScope.app` |

[本版更新与校验文件](https://github.com/qudadd/envscope/releases/tag/v0.25.0-alpha.1) · [所有版本](https://github.com/qudadd/envscope/releases) · [从源码运行](docs/DEVELOPMENT.md)

当前 Windows 包未进行发布者签名；macOS 包使用 ad-hoc 签名，尚未进行 Developer ID 签名或 Apple 公证。首次打开可能被系统拦截。下载校验与签名是不同的验证，详见 [开源构建与更新](docs/OPEN_SOURCE_BUILDS.md)、[正式签名准备](docs/SIGNING.md)。

## 四步使用

1. **确认目标**：填写实际使用地区，读取出口 IP 建议节点国家与城市，匹配时区和地区格式。实际所在地与代理出口分别记录。
2. **一键检测**：查看哪些条件合格、哪里有问题、哪些检查还缺少证据。也可进入“更多功能 → 全部检查”，选择项目或全选。
3. **修复并复检**：审核具体改动后执行，完成后自动复检。需要授权的项目说明用途；不能自动处理的项目提供手动步骤，支持的配置修改保留撤销入口。
4. **按需持续守护**：选择需要保持的配置，预览并确认启用。后台按批准的基线巡检、尝试恢复并记录结果，反复失败会暂停并提醒。

首次打开有使用教学，之后可随时重看。关闭窗口默认驻留托盘或菜单栏；驻留不会自动开启守护。[完整操作说明 →](docs/USER_GUIDE.md)

<details>
<summary>查看桌面界面（离线模拟数据）</summary>

![EnvScope 检测与修复界面，展示问题、权限提示和处理方案](docs/images/desktop.png)

截图展示界面流程，不代表真实 Claude 登录或网络检测结果。

</details>

## 可以做什么

| 你要解决的问题 | EnvScope 提供的能力 | 详细说明 |
|---|---|---|
| 不知道 Claude 为什么连不上 | 代理与 TUN、域名解析、系统选路、TLS、响应状态和耗时，以及桌面版 / Code 配置检查 | [检测与处理](docs/DIAGNOSIS.md) |
| 不知道哪些结果可信 | 分开展示 HTTP、IPv4 / IPv6、原生 UDP 与浏览器观测；每项保留来源、范围和失败原因 | [检查范围](docs/ENVIRONMENT_COVERAGE.md) |
| 配置有问题却不知道怎么改 | 预览 Code 配置、地区时区、Clash Verge 路由、所选 IPv6 接口及客户端修复；确认后执行、读回与复检 | [修复流程](docs/SIMPLE_WORKFLOW.md) |
| 信息读不到，反复出现未知 | 区分权限拒绝、组织策略、超时、缺少工具和本版未支持；适用时引导授权，返回后复检原选择 | [权限与验证边界](docs/PERMISSION_ACCEPTANCE.md) |
| 配好后又漂移，代理掉线 | 周期巡检、批准配置恢复、所选代理客户端重开、Windows / macOS 时区守护及事件记录 | [Watchdog](docs/WATCHDOG_AND_IDENTITIES.md) · [时区守护](docs/TIMEZONE_SERVICE.md) |
| 多个账号的本地资料混在一起 | 独立资料槽位、切换前复检、封存与载入校验、中断恢复入口、加密备份 | [账号资料](docs/ACCOUNT_VOLUMES.md) |
| 想知道变化发生在什么时候 | 脱敏检测历史、修复与守护事件、48 小时出口集合变化、诊断包导出 | [日志与证据](docs/CLI.md) |
| 需要迁移旧工具或更新软件 | 旧后台任务与软件的可恢复迁移、更新包校验、保留前一版本用于回退 | [旧组件迁移](docs/legacy-components.md) · [软件更新](docs/OPEN_SOURCE_BUILDS.md) |

另提供临时浏览器、Windows WireGuard 专项检查、macOS 加密 DMG 兼容和单独启用的进程守护。平台差异、原生实现与兼容入口见 [完整功能对照](docs/FULL_PARITY_AUDIT.md)。

## 怎样理解“环境合格”

合格表示**本次所选范围内，所需证据已取得且符合已确认目标**。未测、超时、不支持和证据过期都会单独显示，不计为通过。

- 本机配置正确、服务有响应，不等于账号能登录或有可用额度；实际回复仍需在自己的 Claude 中确认。
- 系统授权只能解决相应的权限问题。本版尚无权威 DNS 出口、完整进程流量关联和防火墙断网保护；进程守护不等于零泄漏保证。
- 地区预设不等于 Claude 支持地区。修改时区、语言或节点不改变实际所在地，也不保证账号安全或服务端设备判断。
- 诊断只读；修复、账号切换和守护分别审核。配置原文备份可能含凭据，请勿上传；分享诊断包前也应复核。

权限、平台与真实设备的验证范围见 [验收记录](docs/DESKTOP_ACCEPTANCE.md)；数据处理边界见 [SECURITY.md](SECURITY.md)。

## 与 claude-switcher 的关系

EnvScope 以 [claude-switcher](https://github.com/YOURSJEYO/claude-switcher) 为功能参考并随附固定版本源码，在此基础上提供独立桌面交互、检测证据、事务式修复与账号管理。上游原生功能、EnvScope 重实现和需手动处理的项目分别列在 [功能对照表](docs/FULL_PARITY_AUDIT.md)，不将随附源码等同于全部功能已自动可用。

可配合已有 Mihomo / Clash Verge Rev 等客户端使用，不提供账号、代理节点或订阅。Scrapling 只用于开发研究资料采集，不是运行依赖或检测引擎。

## 文档与参与

| 使用软件 | 了解实现 |
|---|---|
| [新用户指南](docs/USER_GUIDE.md) · [选择检查与批量处理](docs/SELECTIVE_CHECKS.md) | [架构](docs/ARCHITECTURE.md) · [开发与验证](docs/DEVELOPMENT.md) |
| [账号资料与恢复](docs/ACCOUNT_VOLUMES.md) · [系统时区守护](docs/TIMEZONE_SERVICE.md) | [命令行](docs/CLI.md) · [开源构建](docs/OPEN_SOURCE_BUILDS.md) |
| [本版更新](docs/releases/0.25.0-alpha.1.md) · [全部文档](docs/README.md) | [正式签名准备](docs/SIGNING.md) · [第三方来源](THIRD_PARTY_NOTICES.md) |

欢迎通过 [Issue](https://github.com/qudadd/envscope/issues) 提交可复现问题，通过 Pull Request 改进代码或文档。请附系统、版本、复现步骤和脱敏结果，不要上传账号资料、密钥或真实代理凭据。

[MIT License](LICENSE)。EnvScope 是独立开源项目，与 Anthropic / Claude 无官方隶属关系。第三方组件保留各自许可，见 [来源与许可](THIRD_PARTY_NOTICES.md)。
