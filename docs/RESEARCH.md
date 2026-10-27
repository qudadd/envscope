# 源码审查与方案取舍

审查日期：2026-10-27。资料通过 Scrapling 抓取，核心代码由 Git 仓库读取。抓取工具不进入产品。完整原始抓取保存在项目外的本地研究目录，公开仓库只保留引用、版本和结论。

## 底座

审查版本：[YOURSJEYO/claude-switcher@870c4ca](https://github.com/YOURSJEYO/claude-switcher/tree/870c4ca0754234965878ef58144d7a755d965037)，MIT。

以完整功能面为底座：锁定并保留 57 个源码文件，使用固定适配器接入原版维护、守护安装、更新和 macOS 加密快照；原生事务式账号交换替代原版切换路径。EnvScope 独立重写检测判定与极简界面，提供原版 `checkdetail` 文本兼容导入，且不把原版 `ok` 继承为独立证据。逐项边界见 [功能对照](FEATURE_PARITY.md)。

| 源码观察 | 对诊断的影响 | 本项目处理 |
|---|---|---|
| [Windows 的 STUN 全无响应返回 `ok`](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/windows/claude-switch.ps1#L181) | 无法区分阻断、超时、服务器故障和其他原因 | 记为未知；加入无响应回归 |
| [Windows DNS 依据 `198.18.*` 判定](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/windows/claude-switch.ps1#L594) | 对非 Fake-IP 模式不通用，也不是权威侧解析出口证据 | DNS 配置作为线索；泄漏结论等待权威观测 |
| [任意非 `000` HTTP 状态可被记为可达通过](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/windows/claude-switch.ps1#L614) | 混合传输响应与应用可用性 | 区分 401、403、429、5xx；不声明登录可用 |
| [原生 STUN 解析只处理 IPv4，未比对 transaction ID](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/core/stun-probe.py#L13) | 对异常报文和双栈覆盖不足 | 重写 IPv4/IPv6 解析及报文校验 |
| [Web 页把部分 IPv6 无结果记为 `ok`](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/docs/app.js#L700) | 不能由无响应推出 IPv6 被保护 | 无结果保留未知 |
| [安全策略明确 10 秒轮询的防护窗口](https://github.com/YOURSJEYO/claude-switcher/blob/870c4ca0754234965878ef58144d7a755d965037/SECURITY.md) | 进程急停不能等同网络层阻断 | 首版不称为 Kill Switch；防火墙单独立项验证 |

这些观察针对锁定版本。macOS 主线已对部分 STUN 规则和运行内核验证做出改进，不能把 Windows 的同类问题泛化为所有平台均相同。

## 其他方案

| 来源与版本 | 采用内容 | 集成方式 |
|---|---|---|
| [WebRTC samples@6e2c5a1](https://github.com/webrtc/samples/tree/6e2c5a117aa860d66d874f7c0df0ef9a3e2cd74e)，BSD-3-Clause | Trickle ICE 收集流程、候选类型与完成事件 | 依据标准 API 独立实现；不捆绑样例应用 |
| [ExpressVPN leak testing@9e4cee8](https://github.com/expressvpn/expressvpn_leak_testing/tree/9e4cee899ac04f7820ac351fa55efdc0c01370ba)，MIT | 将场景、设备配置与测试分离；关注网络变化时的泄漏 | 首版采用故障与误判场景的回归思路；未捆绑其旧依赖或中断网络脚本 |
| [Mullvad 测试框架@0508389](https://github.com/mullvad/mullvadvpn-app/blob/0508389502500fdd8e375d1e53756d4053ca23de/test/README.md)，GPL-3.0 | 主机/虚拟机分离的端到端验证、抓包与跨平台场景 | 仅作后续实验环境参考；不复制其代码 |
| [Mihomo 官方 API 文档](https://wiki.metacubex.one/api/) | `/configs`、`/rules`、`/proxies` | 只读 loopback API 验证模式、规则顺序、目标与当前节点，不嵌入代理内核 |
| [RFC 8489](https://www.rfc-editor.org/info/rfc8489/) | STUN 报文和映射地址规则 | 独立协议实现与合成报文回归 |

ExpressVPN 参考版本的最后提交为 2021 年；采用其测试组织方法，不把旧代码或依赖当作当前跨平台保证。Mullvad 的实现具有不同的部署与许可边界，不将其作为 MIT 组件拼入本项目。

WebRTC 类型解释另核对 [MDN](https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate/type) 和 [官方 Trickle ICE 页面](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)。HTTP 200 抓取若选择器为空，不视为有效方案证据；Trickle ICE 的静态页面首次提取为空后，改为读取其锁定版本源码。

## 当前验证

Windows 完成源码运行、独立程序打包、冻结 worker 的 UDP 本机回环测试及桌面交互检查。规则测试不访问公共 STUN，不切断真实网络，不使用真实账号。macOS 的采集解析器有夹具测试；真实 macOS 系统调用、Safari 和 `.app` 安装体验尚待真机验收。
