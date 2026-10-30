# 开源桌面构建与更新身份

本项目发布源码及 Windows/macOS 独立软件。当前无需商业签名证书：Windows 构建未进行
Authenticode 发布者签名；macOS 使用本地 ad-hoc 签名，不具备 Developer ID 身份，也未公证。
SHA-256 和应用标识用于检查下载与版本一致性，不能证明发布者签名。

应用固定使用 `io.qudadd.envscope`。Windows EXE 的内部名称、文件版本和产品版本，
macOS 的 `CFBundleIdentifier`、`CFBundleShortVersionString`、`CFBundleVersion`，以及
包内 `build-identity.json` 都由同一源码版本生成。升级保持这个应用标识；用户资料沿用原路径。
首次从旧版 `EnvScope` macOS 标识迁移时，系统可能要求重新核对相关隐私权限；打开设置本身
不代表授权成功，回到软件后重新检测实际能力。

更新流程依次核对固定 GitHub 仓库、系统架构、版本、下载大小、GitHub 摘要、发布校验表、
安全解包路径和包内应用身份。新版本安装在旁边的版本目录，保留旧版与资料。主程序或身份
记录在安装后改变时停止启动该更新。现有旧版回退记录仍可用，不会因新增身份文件要求丢失回退。

目前不接受包内自行声称“发布者已验证”或“已公证”的构建。若今后启用正式签名，需要单独
提交并审查发布流程：证书通过仓库秘密配置、固定签发者/Team ID、公证结果读回，并在更新端
校验真实操作系统签名。只添加环境变量或 JSON 标志不能启用此模式。不要将密码、证书私钥
或 Apple 账号凭据提交到仓库。

可重复构建入口：`python -m scripts.build_desktop`。最终包运行
`python -m scripts.packaged_smoke <主程序路径>`，更新路径运行
`python -m scripts.update_package_smoke`。测试使用临时资料，不登录 Claude 或改变真实系统配置。

构建依据：[PyInstaller 应用标识与版本资源](https://www.pyinstaller.org/en/stable/usage.html)。
