# 文档目录

[返回项目首页](../README.md) · [下载桌面软件](https://github.com/qudadd/envscope/releases/tag/v0.25.0-alpha.1)

日常使用从 [新用户指南](USER_GUIDE.md) 开始。只想知道“检查什么、怎么修、如何保持”，按下面对应入口阅读即可。

## 使用与排障

| 要做的事 | 文档 |
|---|---|
| 第一次使用、理解结果、授权与复检 | [新用户指南](USER_GUIDE.md) |
| 按地区与时区完成检测、修复和守护 | [一键流程](SIMPLE_WORKFLOW.md) · [目标环境](TARGET_ENVIRONMENT.md) |
| 选择项目、全选、批量修复 | [可选检查](SELECTIVE_CHECKS.md) · [检查偏好](CHECK_PREFERENCES.md) |
| 查明问题、了解检测证据 | [检测与处理](DIAGNOSIS.md) · [环境覆盖](ENVIRONMENT_COVERAGE.md) · [逐项检查](CLAUDE_CHECKS.md) |
| 确认权限问题和软件能力边界 | [权限验收与限制](PERMISSION_ACCEPTANCE.md) |
| 了解联网与数据处理、停止后台组件及卸载 | [隐私说明](../PRIVACY.md) · [卸载与资料移除](UNINSTALL.md) |
| 比较原项目、平台和实现范围 | [完整功能对照](FULL_PARITY_AUDIT.md) |

## 修复与长期保持

| 功能 | 文档 |
|---|---|
| 批准基线、周期检查、漂移恢复与日志 | [Watchdog](WATCHDOG_AND_IDENTITIES.md) |
| Windows / macOS 系统时区服务 | [时区守护](TIMEZONE_SERVICE.md) |
| 启动或重开代理客户端、TUN 与应用语言 | [客户端修复](CLIENT_REPAIR.md) |
| Clash Verge 路由、IPv6 与 DNS 缓存 | [路由](ROUTING.md) · [网络设置与恢复](SYSTEM_NETWORK.md) |
| Windows WireGuard 与可选进程保护 | [WireGuard](WIREGUARD.md) · [进程守护](PROCESS_GUARD.md) |
| 迁移旧任务、清理旧软件与恢复 | [旧任务迁移](legacy-components.md) · [旧软件清理](LEGACY_SOFTWARE.md) |

## 账号、备份与软件更新

| 功能 | 文档 |
|---|---|
| 独立资料槽位、切换与中断恢复 | [账号资料](ACCOUNT_VOLUMES.md) |
| 加密存档与兼容格式 | [.envsnap 与 CSNAP001](CSNAP_ARCHIVES.md) · [macOS DMG](DMG_ARCHIVES.md) |
| 独立临时浏览器会话与清理 | [临时浏览器](BROWSER_SESSIONS.md) |
| 下载校验、更新身份、版本回退 | [开源构建与更新](OPEN_SOURCE_BUILDS.md) |
| 本版变更 | [0.25.0 Alpha](releases/0.25.0-alpha.1.md) · [所有公开版本](https://github.com/qudadd/envscope/releases) |

## 开发与证据

| 内容 | 文档 |
|---|---|
| 从源码运行、测试、打包和提交改动 | [开发指南](DEVELOPMENT.md) |
| 命令行、策略、报告与证据解释 | [CLI](CLI.md) |
| 模块与安全边界 | [架构](ARCHITECTURE.md) · [安全与隐私](../SECURITY.md) |
| 桌面与权限测试的已验证 / 待验证范围 | [桌面验收](DESKTOP_ACCEPTANCE.md) · [权限验收](PERMISSION_ACCEPTANCE.md) |
| Windows 签名、Apple 签名与公证所需条件 | [正式签名准备](SIGNING.md) · [Code signing policy](../CODE_SIGNING_POLICY.md) |
| 界面与交互原则 | [桌面设计](UI_DESIGN.md) |
| 参考项目、固定版本与许可 | [源码研究](RESEARCH.md) · [来源与许可](../THIRD_PARTY_NOTICES.md) |

[早期功能映射](FEATURE_PARITY.md)、[历史验证记录](VALIDATION.md)、[早期产品验收](PRODUCT_ACCEPTANCE.md)、[可用性测试记录](USABILITY_TESTING.md) 和 [路线记录](ROADMAP.md) 保留阶段背景。判断当前分发状态时，以对应 Release、源码提交和该提交的 CI 结果为准；历史计划不代表新版本已实现。
