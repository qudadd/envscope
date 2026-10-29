# 客户端与 Claude 应用语言修复

0.18 将代理启动、Clash Verge TUN 持久化和 Mac 应用语言从统一旧修复中独立出来。
普通检测继续只读；预览列出具体程序、退出范围及要修改的键，只有布尔值 `true` 的确认才能执行。
这不是代理安装器，不提供节点，也不把启动成功当作连接或账号可用。

## 使用流程

1. 确认实际所在地、使用方式和连接目标，完成新检测。
2. 一键修复需要启动客户端或修复 TUN 时，先预览这一阶段。多个安装同时存在时，到“持续维护 → 客户端与 TUN 修复”读取并选择实际程序。
3. 保存工作后确认。先正常退出已识别的 Claude，不强制退出、不登出、不交换账号资料。
4. 完成后自动复检。根据新读到的网卡与节点预览后续路由、网络和守护改动；只在测得唯一目标隧道时自动带入守护接口。
5. 原生进程守护提交启动后等待新心跳。任务已注册、客户端进程存在或 TUN 配置已开启，都不单独证明全部流量受保护。

“全部检查”可只勾选 TUN / 代理 / 语言等项目，复用相同修复及恢复事务。
未选择的项目不能授权其他修改。客户端变化、过期报告、进程新实例或外部配置修改会要求重新预览。
客户端重启期间持有账号操作锁，阻止同时载入账号或重开 Claude。

## 客户端范围

Windows 从固定安装目录和已知软件的只读卸载注册表识别 Clash Verge、Mihomo Party、Clash Nyanpasu、WireGuard。
不执行 PATH、卸载命令或任意用户输入。Mac 读取已知 `.app` 的 `CFBundleExecutable`，另外支持 Shadowrocket、ClashX / Pro、Surge。
sing-box 没有统一图形入口，按原有服务方式启动，界面提供手动处理。

预览固定程序路径与 SHA256；执行时重查程序、当前用户、PID、创建时间及完整路径。
默认只请求正常退出。正常退出被托盘或未保存内容阻止时停止，保留偏好。
“允许本次强制退出”是独立选项，只针对所选代理，不授权强制退出 Claude；每次操作后清除该选项。
程序摘要用于变化检测，不证明软件来源或商业签名。

## Clash Verge TUN

只在已确认 TUN 目标时提供自动持久化。流程为：

- 保存私有原偏好文件和事务记录。
- 正常退出所选 GUI；退出时若自行保存新配置，保留新配置并停止覆盖。
- 只修改 `verge.yaml` 的 `enable_tun_mode: true`；保留其他字段、注释、订阅、节点和脚本。
- 重开固定程序，分别读取 GUI 偏好、Mihomo 内核 `tun.enable` 及目标域名按地址族抽样的系统选路。
- 缺少服务模式、驱动或系统授权时，由原客户端处理；验证失败尝试恢复 TUN 原值与原先启动 / 停止状态。

优先使用 Clash Verge 配置中的本机 IPC：Windows 命名管道、Mac Unix socket；否则仅接受已声明的 loopback HTTP 控制口。
命名管道在发送认证头前核对服务端 PID、完整内核文件名及用户 SID，限制客户端被模拟的权限，并给连接及读取设定总时限。
失败时不尝试其他端点，不要求用户为了本功能公开控制口。

运行内核的 `PATCH /configs` 不能替代 GUI 持久化，本功能没有只改内核运行标志后就报告修复。
选路验证只覆盖所列目标与地址族抽样，不是 Claude 进程全流量、真实 VPN 驱动或零泄漏验收。
Shadowrocket、ClashX、Surge 等其他客户端的 TUN / VPN 状态仍在原客户端手动处理。

## Mac 的 Claude 应用语言

只按用户明确填写的桌面语言目标处理，不默认设置为英语。
通过系统 Core Foundation 偏好接口读取并保存当前用户的 Claude 专用 `AppleLanguages`：

- 区分缺省、空数组和有序多语言数组。
- 分别保存 AnyHost 与当前 ByHost 原值，读取解析后的有效偏好。
- 已有 ByHost 覆盖一并设置；原来没有 ByHost 键时不创建它。
- 管理策略强制的值不覆盖；陌生类型不转成可通过的值。
- 逐项同步、独立读回；恢复只处理本次语言键，保留其他偏好及全局语言。
- 原来缺省的键恢复为缺省，继续使用当前系统回退语言；不覆盖之后发生的同键修改。

专用偏好读回与应用实际本地化支持分开。需要在 Claude 中确认重开后的界面；系统显示语言不作为通过证据。
Windows 尚无对应自动写入接口，相关检查标红并提供在 Claude 实际设置中确认的步骤。

## 恢复与证据

`~/.envscope/client-repair` / 状态目录中的 `client-repair` 保存客户端私有原件与阶段日志；
`client-language` 保存带类型的语言原值。界面显示实际备份路径。
prepared、writing、starting、rolling_back、partial 等未完成记录阻止覆盖。
重启 EnvScope 后可预览恢复；原副本和后续现场保留，不自动丢弃。

测试层次：

- Python 使用临时配置和伪进程，覆盖过期、拒绝退出、GUI 自行保存、失败恢复、ByHost、缺省、管理策略和中断。
- Playwright 使用离线 Windows / Mac 场景，验证一键分阶段、勾选修复、手动标红、自动复检及恢复入口。
- 原生 CI 编译并启动自己的临时 Cocoa / WinForms 程序，验证正常退出、拒绝退出和本次明确允许的强制退出；不操作真实代理或 Claude。
- Windows 实际命名管道夹具验证认证、未知程序拒绝、超时与清理。
- 两种 Mac 架构只写入唯一一次性测试应用域，使用另一个进程读回；核对真实 Claude 和全局偏好保持一致，最后删除测试键。

真实代理 GUI 重生成、VPN 服务授权、驱动、睡眠恢复以及真实 Claude 界面 / 登录仍需设备验收；测试夹具不会被称为这些证据。

接口来源：[Clash Verge Rev 2.5.8](https://github.com/clash-verge-rev/clash-verge-rev/tree/4337bd85758d54d7b9044b2da3c9ac1176eae1f3)、
[Apple 偏好域读取](https://developer.apple.com/documentation/corefoundation/cfpreferencescopyvalue(_:_:_:_:))、
[Apple 偏好同步说明](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/UserDefaults/AccessingPreferenceValues/AccessingPreferenceValues.html)、
[Microsoft 命名管道模拟权限](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client)。
独立实现公开接口，没有分发 Clash Verge 的 GPL 源码或可执行文件。
