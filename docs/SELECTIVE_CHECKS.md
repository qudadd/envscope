# 可选检查与地区配置（0.11.0 Alpha）

先填写实际所在地、用途和连接方式，再选期望配置的国家与城市。美国、加拿大、澳大利亚
提供多个城市，避免用一个国家代替具体时区。预设填入目标出口国家、系统时区和当前用户
地区格式；观察到的本机值只用于对照，不再直接成为默认目标。自定义目标仍可保留。

“全部检查”有 **全选、取消全选、只选需处理项、勾选筛选结果**。全选覆盖完整目录，
不受搜索或状态筛选影响。检测所选只运行相应网络探测及所需依赖；本机系统资料与共用
配置文件可能一次读取。未选项标明未检测，既不沿用上次结果，也不算通过。缺少必需项时
整体环境保持待完成。账号启动前仍执行完整复检。

检测后点“预览所选修改”，核对原值、目标值和影响，再确认一次。支持：

- Windows / macOS 的预设时区；必要时触发系统管理员授权。
- Windows 当前用户地区格式、macOS AppleLocale；不更改界面显示语言，不强制注销。
- 已有本机 Mihomo / Clash 兼容控制接口里的 Selector 具体节点；不下载订阅，不创建节点，
  不自动选择远程控制接口，不关闭现有连接。修改影响该组后续连接，可能涉及其他应用。
- 已检测出的确定性 JSON 多余逗号、Code TLS、兼容代理 / 路由配置问题；保留原来的
  配置备份与撤销机制。原版核心操作仍列出全部影响，并可能打开交互安装器。

节点目录优先从已知客户端目录或 `ENVSCOPE_CONTROLLER_URL` 读取，只接受 literal
loopback HTTP origin。`ENVSCOPE_CONTROLLER_SECRET` 可用于本机认证；不返回、记录或
导出该密钥。多个控制接口时需明确选择。节点名称不证明国家；切换后的读回只证明当前
选择，再由独立出口检查判断是否符合目标。无兼容接口时需在客户端手动选节点。

原值先写入本机 `~/.envscope/region-recovery.private.json`。权限取消、超时或读回
不一致时停止后续步骤并保留记录。撤销前检查当前值，拒绝覆盖后来手动修改的配置。
部分完成的记录未恢复前不接受新的地区改写。恢复节点可能需要原节点仍在订阅中。
自动时区服务可能覆盖手动时区；在系统设置中按实际需要核对，后台不会强制改回。

无法自动修复的项目标红，展开显示原因、手动步骤、检测本项入口。权威 DNS 出口和
Claude 进程流量关联仍未实现；系统授予更多权限不能代替缺失的测量能力。参考资料与
不适用项保留原状态，中文格式或字体本身不判为账号风险。

实际所在地与期望配置分开保存。中国大陆、俄罗斯等不在当前官方支持名单内的地区，
不能用更换时区、语言或节点消除官方地区失败。部分支持地区仍需人工核对，未确认不自动改写。

验证包括命令白名单、取消授权、陈旧计划、目标漂移、读回失败、节点组变化、恢复冲突、
部分检查不误报合格，以及 Windows / macOS 模拟 UI 流程。外部请求使用夹具或本机
模拟控制接口，系统写入使用注入适配器；**不等于在真实用户操作系统修改成功**。

依据（核对于 2026-10-29）：

- [Microsoft tzutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tzutil)
- [Microsoft Set-Culture](https://learn.microsoft.com/en-us/powershell/module/international/set-culture)
- [Apple systemsetup](https://support.apple.com/guide/remote-desktop/about-systemsetup-apd95406b8d/mac)
- [Apple 语言与地区设置](https://support.apple.com/guide/mac-help/change-language-region-settings-on-mac-intl163/mac)
- [Mihomo 控制 API](https://wiki.metacubex.one/api/)
