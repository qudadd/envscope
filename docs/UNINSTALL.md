# 卸载与本地资料移除 / Uninstall

[项目首页](../README.md) · [隐私说明](../PRIVACY.md) · [文档目录](README.md)

EnvScope 的独立包通过解压运行。卸载前先停止已经批准的后台组件，再退出并删除程序。以下操作均由用户选择；本说明不会执行删除。

## 1. 保留需要的资料，处理待恢复操作

- 如需保留账号槽位、历史或配置备份，先复制到自己的安全位置。原文备份可能含凭据，普通目录复制不提供加密。
- 账号切换若提示“待恢复”，先在账号页完成恢复或保留全部恢复现场，不要直接删除目录。
- 如需撤销已做的配置修改，趁应用仍可运行时使用对应的预览撤销 / 恢复入口，并核对结果。删除软件不会自动恢复系统时区、语言、网络或客户端设置。无法自动撤销的项目按原方案手动处理。

## 2. 分别停止后台组件

在“更多功能 → 持续维护”中检查已启用的组件，并确认停用结果：

| 组件 | 卸载前操作 |
|---|---|
| 周期巡检与批准基线恢复 | 停用持续维护，确认不再执行修复 |
| 可选进程守护 | 单独停用进程守护，确认其任务已停用 |
| 系统时区守护 | 在系统时区服务入口预览并确认移除；需要恢复首次安装前时区时，在该方案中选择恢复，并按系统提示授权 |

**关闭主窗口、退出应用或停用普通巡检，都不会自动移除单独授权的系统时区服务。** 任务移除失败、权限不足或仍有待恢复操作时，保留程序和日志，先按界面提示处理。受组织策略管理的电脑应由管理员协助。

如果曾明确安装原版维护核心，它的后台任务也可能独立存在。在旧组件管理中核对归属和停用方案，或按原版的卸载说明处理；不要将第三方任务一并删除。

## 3. 关闭临时浏览器并退出

关闭由 EnvScope 启动的临时浏览器窗口，在“工具 → 临时浏览器”执行“清理已关闭的临时浏览器资料”，确认没有仍在使用或待重试的资料。无法确认已退出时先保留，不删除日常浏览器目录。

通过托盘或 macOS 菜单栏的退出入口结束 EnvScope；只点窗口关闭按钮可能仍会驻留后台。确认没有仍运行的 EnvScope 工作进程后再移除程序。

## 4. 移除程序与可选本地数据

| 系统 | 程序文件 |
|---|---|
| Windows | 删除你解压得到的 EnvScope 程序文件夹及自行创建的快捷方式 |
| macOS | 将你解压或放入应用程序目录的 `EnvScope.app` 移到废纸篓 |

软件更新可能把新版本保存在用户目录的 `.envscope/updates/versions` 下；完成停用和退出后，才可将这些旧程序副本一并移除。不要删除系统 WebView、Python、代理客户端或其他应用共享的运行环境。

默认保留本地数据便于恢复。如确定不再需要，可在备份后移除下列**属于自己的**目录：

| 目录 | 包含什么，删除前须确认什么 |
|---|---|
| Windows `%USERPROFILE%\.envscope`；macOS `~/.envscope` | 设置、历史、配置备份、更新副本及维护记录；所有关联任务与临时浏览器应已停止 |
| Windows `%USERPROFILE%\.claude-switcher`；macOS `~/.claude-switcher` | 账号槽位和兼容状态；可能由原版 claude-switcher 共用，仅在确认双方都不再使用且恢复已完成后处理 |

不要因卸载 EnvScope 而删除 Claude 的当前资料目录，例如 Windows 的 `%APPDATA%\Claude` 或 macOS 的 `~/Library/Application Support/Claude`。

系统时区服务的移除会保留受保护的备份和日志。其固定路径见 [时区守护](TIMEZONE_SERVICE.md)。如还需彻底移除这些留存记录，应在服务已移除、恢复已完成后由管理员核实路径再处理，不能先删辅助程序来代替停用服务。

移到回收站或废纸篓可留出恢复机会；清空前请再次核对备份。普通删除不等于安全擦除。

## English summary

Before removing EnvScope, preserve any data and recovery records you need, undo
supported configuration changes if desired, and separately disable scheduled
maintenance, the optional process guard and the privileged timezone service.
Use the timezone service's reviewed removal flow and OS authorization; stopping
user maintenance does not remove that service. Resolve pending transactions
before deleting recovery data.

Close temporary browser sessions, finish their approved cleanup, then quit the
tray/menu-bar application and its workers. Remove the extracted Windows folder
or macOS application. Optionally remove your `.envscope` data and update copies
after stopping all components. `.claude-switcher` may be shared with the original
project: preserve it unless both applications no longer need it. Do not delete
the active Claude profile, shared runtimes or third-party proxy software.
Privileged service backups/logs may remain for administrator-reviewed cleanup.
Removing program files does not undo system changes or securely erase data.
