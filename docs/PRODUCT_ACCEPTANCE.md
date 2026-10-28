# 产品交付与验收范围

0.7.1 的操作验收与实际修复详见 [用户操作验收](USABILITY_TESTING.md)：覆盖断线、
功能列表失败、32 项目录、信息就近展示及隔离账号往返；未替用户操作真实登录资料。

目标是帮助 Windows / macOS 用户建立并保持可用的 Claude 环境。以固定版本
claude-switcher 为底座，补齐普通用户从发现问题到处理、复检、进入 Claude 和日常
保持的操作链。软件能交付可复核的操作与证据；服务端账号权限和实际回复由用户在
自己的 Claude 中确认，不能由匿名探测或本地复制资料代替。

## 已实现的需求与证据

| 用户需求 | 当前实现 | 可复核依据 |
|---|---|---|
| 保留原项目功能底座 | 57 文件逐一固定哈希和许可；14 类基础检查；固定维护适配，不运行不安全 Windows 旧切换路径 | `VENDOR_MANIFEST.json`、`scripts/check_release.py`、[逐项对照](FEATURE_PARITY.md) |
| 检测更全面 | 18 项扩展，浏览器与原生观测合并，错误按实际阶段解释 | `tests/test_extended.py`、`tests/test_diagnosis.py` |
| 一条龙操作 | 检测自动出方案 → 一次确认 → 备份与写入 → 自动复检 → 打开 / 正常重开 → 日常保持 | `tests/test_workflow.py`、`scripts/browser_smoke.py` |
| 强化环境设置 | 先测本机 HTTP 代理，再配置 Code；清理匹配绕过项、开启证书校验；自定义 / 云平台保留原路径 | `tests/test_workflow.py`、`tests/test_diagnosis.py` |
| 普通用户能理解 | 三步首次教学、白话解释、六类现象、准确处理入口、逐项保持办法 | `tests/test_guide.py`、三个桌面宽度离线交互 |
| 处理结果可靠 | 修改前后重新取证；无证据不报解决；文件凭据与真实会话分开 | `tests/test_diagnosis.py`、`tests/test_workflow.py` |
| 可进入桌面使用 | 明确确认；新原生检查；安装 / JSON / 账号恢复 / 独立网页目标 / 原有连接条件；正常退出后再复检；同账号锁 | `tests/test_readiness.py`、`tests/test_accounts.py`、`tests/test_desktop.py` |
| 长期保持 | 用户任务 / LaunchAgent；5/15/60 分钟；状态与事件；批准的五个 Code 字段漂移恢复，先备份且有上限 | `tests/test_maintenance.py`、[保持边界](CLAUDE_CHECKS.md) |
| 桌面双平台 | Windows x64、macOS arm64 / x64 独立冻结包；不适配手机 | `desktop.yml`：冻结 worker、资源、原生调度验收 |
| 极简交互 | 黑白、窄侧栏、一个主检测按钮；高级证据按需展开 | [界面约定](UI_DESIGN.md)、1024/1280/1440 截图 |
| GitHub 开源与本地试用 | `qudadd/envscope` 源码、许可、三种桌面包、Python 包、源代码归档及 SHA256SUMS | 对应公开 Alpha Release 与 Actions；本地双击入口 |
| Scrapling 用途 | 只研究、抓取和核对公开项目 / 官方资料，不进入运行时 | `pyproject.toml`、`sources.lock.json`、第三方来源说明 |

## 原生调度的发布关卡

冻结包工作流在隔离 runner 中使用生产 `--maintenance-worker --check-runtime` 入口，
注册真实当前用户任务，等待两次自动执行成功，再移除并独立查询确认消失。
不手动触发任务，不使用假调度器代替该关卡；三个架构全部成功后才发布产物。
JSON 证据保存在每个任务的 `Scheduler-evidence-*` Actions 附件。

这一入口不运行网络探测、读取真实用户维护状态或修改配置。因此它验证调度和打包，
实际网络检测及恢复逻辑另由临时文件 / loopback 回归验证。它不证明跨退出登录、
睡眠恢复、企业权限策略或用户电脑上的具体网络能正常运行。

## 明确保留的边界

- 维护适配所需的原版核心仍需用户明确安装；安装窗口打开不代表安装完成。
- Windows / macOS 实际 Claude 登录、组织认证、系统凭据库、Safari 与签名体验仍需用户设备验收。
- 正常重开只请求退出；无法确认退出时不强制结束，不交换账号资料。
- 当前没有权威 DNS 出口、目标进程全流量关联或原生防火墙断网保护，未知仍保留未知。
- 账号恢复副本、损坏或后续修改的配置不自动清理；备份可能含密钥，只留本机。

以上边界不得在首页、Release 或宣传中改写成零泄漏、账号安全或永久可用保证。
