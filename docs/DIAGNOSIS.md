# 从检测到处理

本版面向用户的交付是“定位问题 → 审核方案 → 执行或打开准确入口 → 复检”，不要求用户阅读 JSON 或从检查项自行归因。原始观测继续保存在脱敏导出中，主界面直接给出原因、顺序和处理步骤。

验收要求：

1. 主界面没有“查看详情”或原始 JSON。问题直接展示检测到的事实、原因或待核实的解释、操作步骤和对应入口。
2. 401 无认证探测不能报成用户密钥失效；403 不推断封号；429 / 5xx 不建议重装本机。curl 5、6、7、28、35、60、77 分别解释。
3. Claude Code 的 SOCKS 不兼容、目标绕过名单、TLS 校验关闭、丢失 CA、错误接口与云提供方开关单独诊断。代理路径差异、TUN 未启用、语言地区差异和缺少可选配置不能直接当成连接故障。
4. 自动处理至少覆盖确定的 JSON 多余逗号、经过测试的 Code HTTP(S) 代理、目标绕过项及恢复 Code TLS 校验。未知语法不猜测修改，不清空 MCP 或账号资料。
5. 每次修改前提供具体影响，只有点击确认执行才写入；仅操作固定配置文件。私有原文备份和恢复记录先于写入，随后原子替换。发现文件变化、链接、过期 / 外来方案时拒绝覆盖。
6. 可跨服务重启校验并撤销配置修复；后续用户或程序已经改过文件时不覆盖新修改。备份含原配置，不能公开分享，退出后仍保留。持续维护的事件撤销会先停用维护。
7. 维护能力进入同一处理方案。安装器打开只表示流程开始；完成安装后继续复检。维护失败必须报告部分完成，不伪称整体修复。
8. 执行后自动重新收集系统与浏览器观测。复检区分已确认消除、仍存在、无法核实与新问题。证据消失不能变成已解决。
9. 支持自动识别、桌面、Code、两者四种范围，减少与当前用途无关的问题。账号启动的严格条件保留，并说明缺少哪项条件以及如何处理。
10. 自动与浏览器测试使用临时配置、模拟维护核心和 loopback；不改变开发机器的代理、地区、账号或服务。Windows / macOS 打包、界面截图和发布包检查覆盖新增模块。

来源已于 2026-10-27 在线核对：

- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)：代理优先级、NO_PROXY、SOCKS 不支持、证书及环境变更生效范围。
- [Claude API 错误](https://platform.claude.com/docs/en/api/errors)：401 / 403 / 429 / 5xx 语义；本工具未发送凭据，因此不推断用户账号状态。
- [curl 错误码](https://curl.se/libcurl/c/libcurl-errors.html)：解析、连接、超时、TLS 与信任文件错误。
- [Code 设置](https://code.claude.com/docs/en/settings)与[安装登录排障](https://code.claude.com/docs/en/troubleshoot-install)：配置位置、作用域、PATH 与重新启动。
- [Windows 设置 URI](https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings)：固定的代理、日期时间和存储入口。
- 上游 [#1](https://github.com/YOURSJEYO/claude-switcher/issues/1)、[#17](https://github.com/YOURSJEYO/claude-switcher/issues/17)、[#21](https://github.com/YOURSJEYO/claude-switcher/issues/21) 用于理解真实反馈；它们不作为当前机器已经发生相同故障的证据。运行规则继续从内核读取，不以静态规则文本存在为成功。

原始抓取在开发研究目录中保留，项目只分发来源、摘要与哈希，不分发网页副本。Scrapling 仍是开发收集工具。

自动化边界：本工具不能替用户完成组织认证、取得可信企业根证书、恢复服务端额度或修复第三方服务故障。这些情况仍给出具体的官方入口和后续步骤，并明确没有执行本机修复。
