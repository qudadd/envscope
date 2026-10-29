# Windows WireGuard 专项检查

0.19 增加独立的 WireGuard 模式。先在目标设置选择“WireGuard（Windows）”，
连接方式随之设为 TUN / VPN。读取后选择本次使用的隧道；只有一个隧道时才允许
自动识别，多个隧道不会猜测。读取不会激活隧道、安装驱动或查看 VPN 配置内容。

## 检测与处理

| 结果 | 依据 | 处理 |
|---|---|---|
| 服务在所列范围通过 | 指定服务的 SCM 登记、独立进程 PID、完整程序路径、创建时间和程序文件摘要已读回 | 继续检查对应网卡与目标路由；服务运行不等于已连通 Claude |
| 服务未运行 / 未找到 | 服务列表完成读取，指定服务停止、暂停或不存在 | 在 WireGuard 客户端激活所选隧道，随后复检；不自动更换隧道 |
| 多个隧道待选择 | 取得多个服务，目标尚未指定 | 在目标设置选择本次使用的一个 |
| 权限被拒绝 | Windows 明确拒绝读取服务或所属进程 | 审核后可打开系统服务管理器；由管理员核对读取权限，之后复检。打开入口不代表已授权 |
| 身份或读取不完整 | 配置不在识别范围、程序不匹配、检查中发生重启 / 替换、过渡状态或超时 | 保留未知并展示原因；核对官方安装与所选隧道，不把同名进程当作成功 |
| 目标选路不合格 | 已核实服务，但所查目标地址走其他网卡或拒绝路由 | 在所选隧道核对 AllowedIPs、IPv6 和激活状态，处理后复检 |

“全部检查”新增可单独勾选的“WireGuard 隧道服务”。无法自动处理的项标红并
保留具体步骤；勾选服务检查不会授权改写 DNS、系统时区、VPN 密钥或账号。
已识别的 Windows WireGuard GUI 可在“客户端与 TUN 修复”中审核后启动，
程序启动和隧道激活分别验证。WireGuard 的 AllowedIPs 和密钥由官方客户端管理，
不会给它写入 Clash 专用规则或把 Clash 控制器未提供判为它的故障。

## 守护基线

原生进程守护固定一个具体服务、程序完整路径、SHA-256 及同名隧道网卡。
每 10 秒重新检查，其他 VPN 在线不能替代。服务停止、读取失败、网卡离线或
程序摘要变化时，按已批准范围停止当前用户已识别的 Claude 桌面进程并留痕。
原生守护仍需要新心跳才能算运行；仅注册任务不算生效。

程序更新后重新检测并审核新摘要，不能默默把新文件加入旧基线。系统目标改变
会暂停旧方案。正常停止、两秒后强制停止和读回规则沿用[进程守护](PROCESS_GUARD.md)。
守护不会自行启停 Windows VPN 服务、重开 Claude、交换账号或修改网络。

## 读取范围与来源

官方 Windows 客户端为每个隧道建立独立 `WireGuardTunnel$名称` 服务，配置文件名
决定服务名称；见 [WireGuard 企业部署文档](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)。
网卡名来自其配置名称，见 [官方隧道实现](https://git.zx2c4.com/wireguard-windows/tree/tunnel/service.go)。
读取服务命令只使用 `CommandLineToArgvW` 解析，绝不执行该命令；只认可固定
Program Files 安装位置的 `wireguard.exe`、`/tunnelservice` 和匹配名称的配置参数。
报告不保留配置路径或命令原文，不打开 `.conf` / `.conf.dpapi`，分享报告隐藏隧道名称。

通过只读注册表枚举名称，再逐个查询 SCM，避免 [EnumServicesStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw)
在无服务读取权限时静默省略记录。只接受 [SERVICE_WIN32_OWN_PROCESS 与运行态 PID](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process)，
核对服务账户、持有的进程句柄信息并再次读取服务与文件，变化时不通过。
摘要是变更检测，不是数字签名或发行方认证。

此专项仅支持 Windows 官方客户端安装布局；macOS WireGuard 的 Network Extension
不等同 Windows 服务，macOS 用户仍使用通用 VPN 检查并在实际客户端确认状态。
本版不验证 WireGuard 对端握手或 Claude 进程的所有数据包，不承诺零泄漏。

## 验证

- Python 场景覆盖停止、缺失、多隧道、身份不匹配、进程号复用、程序替换、
  超时、权限拒绝、错误网卡、错误选路及基线重审。
- 离线桌面 UI 在 1024 / 1440 宽度验证选择、检测、预览、守护、断线留痕与停用。
- Windows CI 编译自己的无网络临时服务，使用真实 SCM / 进程 API 读回运行与
  停止状态，完成后删除它。它不创建网卡、不安装 VPN 驱动、不使用真实凭据。
- 实际 WireGuard 驱动、真实 VPN 连接、睡眠恢复与真实 Claude 会话仍需设备验收；
  临时服务验证不能替代这些证据。
