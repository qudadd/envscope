# 开发与验证

[项目首页](../README.md) · [文档目录](README.md) · [命令行与检测证据](CLI.md)

产品面向 Windows 和 macOS。Linux CI 用于规则与页面回归，不代表提供 Linux 桌面版。开发前阅读仓库根目录的 [AGENTS.md](../AGENTS.md) 与 [安全边界](../SECURITY.md)。

## 从源码运行

需要 Python 3.10+。系统 `curl` 用于在线 HTTP 检测；Windows 桌面窗口使用 WebView2，macOS 使用 WKWebView。下载仓库源码后，在仓库目录运行：

```sh
python -m pip install '.[desktop]'
python -m envscope desktop
```

也可双击 Windows 的 `start-windows.cmd`，或在 macOS 运行 `start-macos.command`。浏览器兼容入口为 `python -m envscope desktop --browser`；只需命令行时安装 `python -m pip install .` 即可。更多参数见 [CLI](CLI.md)。

日常用户应直接使用自带运行环境的 [桌面包](https://github.com/qudadd/envscope/releases/tag/v0.25.0-alpha.1)，无需安装开发工具。

## 本地检查

在仓库根目录执行：

```sh
python -m unittest discover -s tests -v
node --test tests/browser.test.mjs tests/permission_flow.test.mjs
node --check envscope/web/app.mjs
node --check envscope/web/permission_flow.mjs
node --check envscope/web/workspace_ui.mjs
python -m scripts.check_release
python -m pip wheel . --no-deps --wheel-dir dist
python -m scripts.verify_package dist
```

修改其他 JavaScript 模块时也要检查相应文件语法。完整 CI 检查列表见 [checks.yml](../.github/workflows/checks.yml)，不要只以这里列出的几个模块替代全部发布检查。

页面交互和视觉验收使用 Playwright：

```sh
python -m pip install playwright
python -m playwright install chromium
python -m scripts.browser_smoke
python -m scripts.simple_workflow_smoke
python -m scripts.permission_flow_smoke
python -m scripts.desktop_refresh_smoke
```

按改动范围补跑对应脚本；完整发布矩阵以工作流为准。测试只使用合成资料、临时目录和 loopback 服务，不修改开发者真实时区、代理、账号或后台任务，不使用真实 Claude 凭据。

## 桌面构建

在对应 Windows / macOS 主机安装构建依赖后运行：

```sh
python -m pip install '.[desktop]' 'pyinstaller>=6.10,<7'
python -m scripts.build_desktop
```

也可运行 GitHub Actions 的 [desktop packages](../.github/workflows/desktop.yml)。构建包括 Windows x64、macOS ARM64 与 Intel；以各自架构的实际构建和验收结果为准。

macOS 加密依赖需静态链接 OpenSSL，构建脚本会检查；Intel 的 Rust、OpenSSL 与源码构建设置见工作流。最终用户不需要这些构建工具。当前 Windows 包未签名，macOS 使用 ad-hoc 签名。身份与摘要的意义见 [开源构建](OPEN_SOURCE_BUILDS.md)，正式发布者签名的准备工作见 [SIGNING.md](SIGNING.md)。

## 改动与发布要求

- 修复必须保持“预览影响 → 用户确认 → 写入 → 读回 / 复检”的流程；缺少证据、取消授权和部分失败不能转成通过。
- 上游随附文件是固定摘要的来源资料，保留原字节和许可证；不要执行其测试、安装器或脚本来替代本项目回归。
- 不提交真实报告、账号卷、凭据、浏览器资料或研究抓取原文。配置原文备份可能含密钥，也不得作为测试夹具。
- 提交 Pull Request 时写清问题、结果、适用平台与已运行的验证；区分模拟测试、真实 OS 夹具和人工设备验收。
- 发布检查包括 Python / JavaScript、页面与视觉、包构建与内容、三架构桌面和更新流程。正式签名启用后还需加入实际签名与公证验证。

## 当前版本证据

0.25.0 Alpha 的测试源提交为 `e7cd61d0e8f1884441a1845c5a72f429102ae300`：

- [规则、页面与包内容 CI](https://github.com/qudadd/envscope/actions/runs/41045089026)
- [三架构桌面与原生隔离验收 CI](https://github.com/qudadd/envscope/actions/runs/41045082167)
- [桌面验收范围](DESKTOP_ACCEPTANCE.md) · [权限验收范围](PERMISSION_ACCEPTANCE.md)

这些结果不证明真实 Claude 登录、服务端设备识别、所有第三方 VPN 驱动或人工 UAC / TCC 场景已经通过。后续提交应引用自己的测试记录。
