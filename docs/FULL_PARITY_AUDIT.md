# 完整功能升级核对表

核对范围是 claude-switcher 的 Windows / macOS 功能、交互与维护流程，参考版本固定为
[`92cd62f95f98599215995406deaa7edd89c97c40`](https://github.com/YOURSJEYO/claude-switcher/tree/92cd62f95f98599215995406deaa7edd89c97c40)，核对日期 2026-10-30。
Linux 和手机端按产品范围延后。随包 57 个上游文件仍固定在 `870c4ca`，未改写其字节。

当前 0.23 源码已将所列功能映射到原生实现或明确的兼容 / 手动入口。发布前仍须通过
对应提交的三平台 Python、20 组浏览器流程、三架构桌面包及实际 OS 夹具验收。
本文列的是实现与证据范围，不把候选版本、模拟账号或静态表格当作已发布或真实登录成功。

## 功能映射

| 上游功能 | EnvScope 实现与入口 | 验证和边界 |
|---|---|---|
| check / checkdetail，基础审计 | 一键检测、全部检查、57 项可检索目录；逐项证据、问题、修复和保持方案 | baseline / probes / check_catalog / inspection；未测、失败、权限不足、不适用分开显示 |
| set-check-config，可选检查 | 持久偏好，一键、所选项目与后台共用；必要依赖不能关闭 | CHECK_PREFERENCES；跳过不算通过，不绕过 TLS 或地区条件 |
| status，A–D 卡片和命名 | 原生 AccountManager，另支持自定义槽位；体积、日期、当前与待恢复状态 | accounts 与账号 UI；本机状态不等于服务端订阅或认证验证 |
| switch，首次收编、空槽登录、启动 | 正常退出、完整目录独立复制 / APFS COW、摘要、重命名、指针读回、事务恢复 | ACCOUNT_VOLUMES；失败与实际测试子进程中断均保留副本；不调用登出或伪造设备标识 |
| 暂存冲突、指针与清理 | 独占锁、v2 日志、提交后清理；清理失败保持已提交指针并阻止启动，恢复入口可继续处理 | 覆盖上游 92cd 的目录冲突 / 指针不一致故障；EnvScope 使用自己的 `.new` / `.previous` 与恢复协议，不执行其 cleanup.json 删除路径 |
| keep-in-workspace | 显式 skills 白名单、暂存合并、目标存档保持独立 | settings、OAuth、Cookie、身份文件不跨账号共享；旧越界清单停止并指导修正 |
| fix，一键设置与复检 | 先修客户端，再读取实际连接，预览 Code、地区、路由、网络与守护；确认后执行并复检 | workflow / SolutionPlans / region_setup；按新结果分阶段，不提前批准尚未出现的网卡 |
| 代理客户端选择 / 识别 | Clash Verge、FlClash、Shadowrocket、sing-box、ClashX、Surge、WireGuard 等分型；批准所选程序后启动 / 正常重开 | CLIENT_REPAIR / WIREGUARD；无统一管理 API 的开关在原客户端处理，不把进程存在当作 VPN 生效 |
| Clash TUN 偏好保持 | 原生持久化、原配置备份、重开与内核 / 目标选路读回、失败和中断恢复 | 实际本机内核及惰性客户端夹具；第三方真实 GUI / 驱动另行核对 |
| set-region，时区、地区格式、语言 | 实际地区单列；出口 IP 双来源建议、国家城市联动、预览 / 系统授权 / 写入 / 读回 / 撤销 | TARGET_ENVIRONMENT；名单按当前官方帮助和 API 页面核对，不提前启用 2026-11-12 的新法律页面 |
| 13 域名和 3 组 STUN UDP 规则 | 原生 Clash Verge 脚本保留、置顶规则、加载读回、回滚与恢复 | ROUTING；用独立临时 Mihomo 实核验证；其他客户端给出逐条手动规则 |
| IPv6 / DNS 设置 | 选择 / 全选接口、备份、系统授权、独立读回、失败回滚、中断恢复 | SYSTEM_NETWORK；缓存刷新单独说明不可撤销；DNS 配置不冒充权威 DNS 出口 |
| Claude 应用语言 | Mac 原生 typed preference、默认 / 多语言 / ByHost 恢复；Windows 手动入口 | CLIENT_REPAIR；偏好值读回与实际应用界面分开 |
| diagnose-proxy | 原生 HTTP / HTTPS / SOCKS5 / SOCKS5h、TLS、各目标响应与错误归因 | 失败不回退直连；匿名 401 只证明服务端响应，不证明登录可用 |
| fingerprint | 原生字体目录计数、GPU / 显示、系统 / 虚拟化线索和按需浏览器资料；原版 Mac 详细入口保留 | environment_info / coverage；不复制中文字体等同风险、STUN 等同浏览器 WebRTC 等未经证实的结论 |
| cli-info | PATH / 实际路径、多入口、可信包元数据、来源和配置体积；原版 Mac 详细入口保留 | cli_inventory；无可信版本元数据时给出终端命令，不自动执行 PATH 中任意程序 |
| open-safe | 两平台独立临时资料、允许网址与代理参数检查、UDP 选项、独立隐藏清理进程、重启恢复 | BROWSER_SESSIONS；真实无害父子进程退出与冻结包夹具；不等于浏览器内部状态或防火墙验证 |
| snapshot-export / import | 原生跨平台 ENVSNAP1、原版 Windows CSNAP001、Mac 原版加密 DMG | CSNAP_ARCHIVES / DMG_ARCHIVES；密码经内存 / stdin、先认证、边界限制、空槽、独立 .NET 交叉验证与逐文件回读 |
| 10 秒进程守护 | 独立用户任务、固定 PID / 用户 / 路径和批准基线、心跳、冷却与日志 | PROCESS_GUARD；只停止已识别 Claude；是轮询，不是零数据包泄漏保证 |
| 时区 Watchdog / 漂移恢复 | Mac root 60 秒服务与用户巡检；Windows 批准基线恢复；安装 / 更新 / 撤销 / 中断恢复 | TIMEZONE_SERVICE / WATCHDOG_AND_IDENTITIES；权限不足转手动，旧守护冲突时暂停自动写入 |
| 后台维护 / 代理离线 | 审核过的配置保持、所选客户端重开、节点恢复、冷却、复检、按日日志 | maintenance / watchdog；新目标需要新批准，不在后台随意切换账号或国家 |
| 48 小时出口历史 | 观测次数、不同出口集合数、变化次数分别展示；HMAC、过期清理、缺样本说明 | maintenance / watchdog；集合不等于单个 IP，密钥轮换后不延续不可比计数 |
| 安装、更新、卸载维护组件 | 原生组件各自安装 / 更新 / 可逆移除；固定旧安装器兼容入口保留 | 系统权限由本次 OS 授权，第三方驱动仍用原客户端；不把 CI 提升权限等同实际授权弹窗验收 |
| 完整旧软件清理 | 一次预览确认先停用旧任务，再存档所选核心、界面、快捷方式、App、模板和固定系统脚本；可恢复 | LEGACY_SOFTWARE；未知文件保留，账号 / 凭据 / 配置保留；恢复文件不隐含启动旧任务 |
| update，自动更新检查 | EnvScope 完整包检查、下载校验、替换、重启与失败回滚；可后台检查；旧核心更新单列 | updates / update-package-smoke；校验和不等于发行者签名或 Apple 公证 |
| UI、常驻、教学 | 极简桌面 UI、首次教程、用途与城市目标、单项 / 全选、合并修复、托盘隐藏 / 唤回、自动复检 | desktop / usability / target / selection / software 等离线场景与三架构窗口 / 托盘验收 |
| 日志、导出和历史对比 | 按范围留痕、历史比较、受限命令日志轮替、可关闭 / 清除、固定白名单诊断 ZIP | diagnostics / history；默认脱敏，不导出账号卷、凭据、浏览器资料或任意目录 |

## 证据解释

`tests/` 验证失败边界与数据一致性；浏览器脚本验证实际按钮、确认前不写入、手动说明和自动复检；
CI 的惰性任务 / 临时文件证明真实 Windows 调度器、Unicode Shell Link、DACL、macOS launchd、
root 文件事务等操作范围；冻结包验证依赖、原生窗口、托盘、导出和恢复入口。

真实 Claude 登录、钥匙串 / DPAPI 跨设备迁移、所有第三方 VPN 驱动、服务器设备识别和物理断电
不在这些夹具的证明范围内。它们作为明确限制保留，不伪造通过，也不要求使用真实凭据才能完成
本次用户已同意的模拟环境实现与软件发布。后续上游新提交按新的固定参考版本另行审阅。
