# 权限与后台升级验收

本表区分实现、隔离测试和真实用户设备观察。测试中的允许/取消/拒绝响应，不代表已由
真实用户点击 UAC/TCC。开发和回归测试不修改用户的实际时区、网络、应用或账号。

| 审查项 | 已实施 | 验证入口 | 设备边界 |
|---|---|---|---|
| 子项失败但汇总通过 | 结构化子项错误传递到汇总及依赖项 | `test_inventory_permissions` | 模拟 Windows/macOS 拒绝、超时、部分结果 |
| 授权用途及续检 | 按检查和目标给入口，返回后一次复检，目标变更作废旧续检 | `test_permissions`、`permission_flow.test.mjs`、`permission_flow_smoke` | 系统设置与授权响应使用夹具 |
| 后台写入权限 | 原用户能力预检；缺权时前台批准原生系统时区任务；每轮重验 | `test_watchdog`、`test_windows_timezone_service`、`test_timezone_integration` | 原生调度的真实周期另列于发布 CI |
| 取消和半完成操作 | 区分取消、策略拒绝、执行失败和超时；保存受保护事务供恢复 | `test_consent`、时区/网络/迁移事务测试 | 不由退出码假设没有发生写入 |
| 应用身份与更新 | 固定应用 ID、原生版本资源、更新包身份和摘要核对 | `test_app_identity`、`test_desktop_runtime`、冻结包与更新烟测 | Windows 未签名；macOS ad-hoc；正式签名按开源交付范围延期 |
| 权限变更及异常提醒 | 停用、其他用户归属、心跳过期、文件篡改、反复修复暂停、去重通知 | `test_guard_notifications`、原生服务与后台测试 | 真实用户授权撤销、重启及睡眠唤醒尚待专用设备验收 |

Windows 原生验收 `scripts.windows_timezone_acceptance` 只在明确启用的 CI 管理员会话中
运行，使用唯一任务名与文件模拟时钟。它验证 SYSTEM 自动周期、可写 ACL 拒绝、移除与
恢复、撤销和事务中断恢复；执行前后比较真实 `tzutil /g`。macOS 的对应入口为
`scripts.timezone_acceptance`，使用唯一 fixture 路径及真实 LaunchDaemon，并核对
`/etc/localtime` 未改变。fixture 辅助程序不进入发布包。

0.25.0 Alpha 发布源提交的本地完整回归：运行 726 项 Python 测试（5 项平台跳过，其余通过），19 项 JavaScript 测试通过；
真实 Windows 冻结包和离线更新包的窗口、托盘、隐藏、恢复、退出与版本身份检查通过。
该版源提交 `e7cd61d0e8f1884441a1845c5a72f429102ae300` 的
[检查 CI](https://github.com/qudadd/envscope/actions/runs/41045089026) 与
[三架构 desktop packages](https://github.com/qudadd/envscope/actions/runs/41045082167) 已通过。
后续版本以自己的提交、运行结果与对应产物为准；未成功的运行不计为通过。

后续专用设备矩阵仍待执行：普通用户首次允许/取消、组织策略拒绝、运行中撤权、升级后
再次打开、系统重启、睡眠唤醒。当前开源 Alpha 可继续交付，但不得将这些待验证场景写成
已通过。正式签名与公证不是当前交付前提，也不替代任何 OS 权限检查。

权限无法补齐未实现的检测：权威 DNS 出口、完整进程流量关联、Claude 登录、账号额度与
实际回复各有自己的证据来源；超时、未实现和缺少认证不应一概显示为“申请权限即可修复”。
