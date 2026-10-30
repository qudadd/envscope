# 正式签名准备

[项目首页](../README.md) · [开源构建与更新](OPEN_SOURCE_BUILDS.md) · [文档目录](README.md)

核对日期：**2026-10-30**。适用于通过 GitHub Releases 分发的 Windows / macOS 桌面包。申请资格、价格与服务政策可能变化，提交申请前应再核对下方官方页面。

## 目前处于什么状态

EnvScope 是 MIT 开源项目，可以继续免费分发源码和软件。正式签名用于让操作系统验证发布者与文件完整性，不要求项目转为商业软件。

| 项目 | 当前公开的 0.25.0 Alpha | 正式发布者签名所需路径 |
|---|---|---|
| Windows | EXE 未作 Authenticode 发布者签名 | 受 Windows 信任的代码签名服务或证书、签名时间戳与验证 |
| macOS | ad-hoc 签名，无 Developer ID，无公证 | Developer ID Application 签名、Hardened Runtime、Apple 公证及票据附加 |
| 更新器 | 校验仓库、架构、版本、SHA-256 与应用标识 | 还需接入真实操作系统签名和发布者身份验证 |

校验和、Git 提交上的 Verified 标记和软件的发布者签名各有不同用途。目前没有申请结果、证书或公证通过记录，不应在下载页展示“已签名”。

## Windows：先选择签名来源

| 路径 | 需要准备 | 对 EnvScope 的适用情况 |
|---|---|---|
| SignPath Foundation 开源支持 | 公开源码和发布包、开源许可、可追溯构建、维护与审核角色；提交项目审核 | 可先评估申请，是否接受由基金会审核决定 |
| 公共受信任 CA 的代码签名证书 / 云签名 | 真实个人或组织身份；选择接受申请人所在地与主体类型的服务商；硬件令牌或 HSM / 云签名环境 | 不依赖开源资助审核，费用与资格由供应商确定 |
| Microsoft Artifact Signing（原 Trusted Signing） | Azure 订阅、Entra 租户、身份验证、证书配置文件；申请主体须满足支持地区条件 | 需先核对身份所在地，不能只看 Azure 部署区域 |

**SignPath 有额外约束。** 其免费证书的发布者是 SignPath Foundation；项目需满足开源组成、项目声誉、构建来源、成员多因素认证、签名审批和公开签名政策等要求。诊断类功能是否符合其限制，需要如实提交审核。本项目尚未获批，不预先声明受其签名支持。[官方条件](https://signpath.org/terms) · [申请入口](https://signpath.org/apply)

**购买证书不再等同于取得一个可随意复制的私钥文件。** 新签发的公共代码签名证书通常要求私钥处于合规硬件令牌或 HSM 中；云签名可由服务商管理硬件。购买前需确认能否用于 GitHub Actions、身份显示名称、时间戳服务和续期流程。[DigiCert 私钥存储要求](https://knowledge.digicert.com/alerts/code-signing-changes-in-2023)

**Microsoft 的地区资格需要单独核对。** 当前公共信任服务面向指定地区的组织，个人申请仅支持美国与加拿大；中国大陆不在当前组织支持名单中。如果以中国大陆个人或组织申请，不能将这条路线视为已可用，也不能用改变云区域代替身份资格。[Microsoft 官方前提条件](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)

Windows 签名应覆盖本项目的主程序和特权辅助程序；若以后增加安装器，也需纳入。先签最终程序字节、加时间戳并验证，再生成发布包和摘要。第三方组件保留自己的来源与签名，不冒充由 EnvScope 开发。[SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)

有效签名也不保证新软件立即消除所有 SmartScreen 提示；系统还会参考文件和发布者信誉。[Microsoft SmartScreen 说明](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)

## macOS：个人开发者也可以申请

| 项目 | 要准备的内容 |
|---|---|
| Apple Developer Program | Apple 账号、双重认证、真实身份与联系方式；个人通常无需成立公司 |
| 组织身份（可选） | 合法组织、签约授权、D-U-N-S 编号、组织域名邮箱与网站；特殊机构按官方例外处理 |
| 费用 | 标准会员费为 **99 美元 / 年**，当地币种与实际结算以 Apple 为准；开源本身不自动免除年费 |
| 签名证书 | Developer ID Application，用于 GitHub 下载的 `.app`；如果另做 `.pkg` 安装器，再准备 Developer ID Installer |
| 构建与公证 | macOS / Xcode 工具链、签名私钥受控保存、公证认证方式及 Team ID |

个人与组织的注册条件和费用见 [Apple 官方注册说明](https://developer.apple.com/programs/enroll/)。申请主体决定签名身份，不能将仓库昵称直接当作已验证的法人名称。

Developer ID 证书通常由 Account Holder 创建；Apple 另外提供有特定授权的云管理证书路径。证书的用途必须区分 Application 与 Installer，普通开发证书或 ad-hoc 签名不能替代 Developer ID 分发签名。[Developer ID 官方说明](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)

正式构建需要正确签署嵌套程序与辅助程序，启用 Hardened Runtime，设置所需的最小 entitlements 并带安全时间戳。随后使用 `notarytool` 提交公证，读回成功结果与日志，再附加并验证公证票据。公证后重新打包，最终下载文件的 SHA-256 才能用于发布校验。[Apple 公证说明](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) · [自定义公证流程](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

## 本仓库还需要完成的接入

拿到证书后仍需修改构建与更新逻辑。当前 `build-identity.json` 明确表示未验证发布者；更新器拒绝仅在文件内自行改成“已签名 / 已公证”的构建。

1. **固定发布身份**：明确 Windows 发布者与 Apple Team ID，记录允许的证书更换策略。
2. **接入受控签名**：为 Windows 主程序、时区辅助程序和 macOS 嵌套代码建立签名步骤；私钥留在硬件 / 密钥库 / 受控签名服务中。CI 使用最小权限及受保护的发布凭据，不在日志里输出秘密。
3. **调整打包顺序**：先签特权辅助程序，再固定其载荷摘要与包内身份，随后完成主程序 / `.app` 签名并读回验证。macOS 公证成功并附加票据后，才生成最终分发包和校验表；不在最终签名后改写包内身份文件。
4. **更新端真实验证**：调用平台验证能力核对签名、发布者或 Team ID、证书链与公证状态；验证从旧未签名版升级、回退、证书轮换及损坏包拒绝。
5. **验证再发布**：Windows x64、macOS ARM64 / Intel 分别验收下载后的首次打开、UAC / 系统授权、后台守护、更新与卸载。仅凭 CI 上传成功不能宣称已完成公证或用户授权。

实现入口：[构建身份](../envscope/app_identity.py)、[桌面打包](../scripts/build_desktop.py)、[更新器](../envscope/updates.py)、[桌面发布工作流](../.github/workflows/desktop.yml)。

签名不会自动授予管理员、文件访问或后台服务权限；这些仍由系统与用户按实际操作批准。签名也不证明 Claude 账号、订阅或地区使用条件符合要求。

## 适合当前开源阶段的顺序

先确定以个人还是组织名义发布。Windows 可以先评估 SignPath 开源申请，同时了解支持真实申请主体的 CA / 云签名报价；macOS 可走个人 Apple Developer Program。选定方案并取得身份与证书后，再实施上述发布流水线改造。

账号注册、付费和申请应由维护者在官方站点完成。不要在 Issue、聊天、源码或普通构建产物中提交身份证件、密码、私钥、`.p12` / `.pfx` 或公证凭据。
