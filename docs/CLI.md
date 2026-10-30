# 命令行与检测证据

[文档目录](README.md) · [桌面入门](USER_GUIDE.md)

## CLI

需要 Python 3.10+；在线 CLI 检测还需要系统 `curl`。浏览器页面无第三方 JavaScript/CSS 依赖。

下载本仓库源码后，在源码目录中运行：

```powershell
cd envscope
python -m envscope --help

# 默认仅采集本机只读信息，不向公共服务发探测请求
python -m envscope audit --html reports/audit.html

# HTTP + 原生 UDP STUN + IPv6；公共端点会看到探测来源地址
python -m envscope audit --online --stun --ipv6 --html reports/audit.html

# 当前浏览器的真实观测；在浏览器打开输出的 loopback 地址
python -m envscope serve
```

命令行可 `python -m pip install .` 后使用 `envscope`。源码运行独立窗口请安装 `python -m pip install '.[desktop]'`；浏览器兼容入口是 `python -m envscope desktop --browser`。Windows 和 macOS 的系统适配器读取各自的网卡、路由和 DNS 配置；配置存在不能证明流量已接管。

退出码仍按选定验证范围：`0` 范围内通过，`1` 明确策略或目标不符，`2` 证据不完整或需要复核，`3` 输入/本地资源错误。连接诊断显示“服务有响应”时，完整隐私范围仍可能返回 `2`；这是覆盖不足，不等于服务不可用。默认离线运行返回 `2`，不是程序崩溃。

## 检测规则的升级

| 观测 | EnvScope 的解释 |
|---|---|
| STUN 超时、IPv6 无响应 | 未知，不能推导“零暴露”或“已关闭 IPv6” |
| 原生 UDP 有响应 | 只说明原生 UDP 路径；与浏览器 ICE 分开 |
| HTTP 200 但 IP 响应结构无效 | 未知；验证码页面不会成为有效 IP 证据 |
| HTTP 401 / 403 / 429 / 5xx | 分别标注认证、访问拒绝、限流、服务异常 |
| UDP/ICE 与 HTTP 出口不同 | 无明确允许地址时提示复核，不直接宣称“真实 IP 泄漏” |
| 观测地址超出用户明确配置的允许 CIDR | 策略违反；不推断地址所有者或物理位置 |
| 只有 mDNS、私网或 TURN relay 候选 | 没有可比较公网候选，保留未知 |
| TUN 网卡存在、代理进程存活、Fake-IP、DoH 可达 | 配置或行为线索，不能替代实际路径验证 |
| 中文语言、时区、ASN 机构名 | 不用于推断账号安全、住宅属性或封禁概率 |
| 上游 `checkdetail` 报告中的 `ok` | 导入为“未独立重测”，不继承通过结论 |

默认 `privacy` 范围要求 IPv4、IPv6、UDP、浏览器和权威 DNS 证据。若只检查 HTTP 传输，可明确选择 `--profile transport`；此时 `0` 也只表示所选范围内通过，其他未知项仍展示。

## 配置允许地址

创建不会提交到 Git 的 `policy.private.json`。下面地址是文档示例，请替换成自己**明确知道应当使用的**出口网段；不要直接把待测结果自动学习成可信范围。

```json
{
  "allowed_ipv4": ["203.0.113.10/32"],
  "allowed_ipv6": ["2001:db8:1234::/48"]
}
```

```powershell
python -m envscope audit --online --stun --ipv6 --policy policy.private.json
```

允许列表区分 IPv4/IPv6，可配置多个合法出口。没有列表时，仅报告同一场景内的一致性或差异。CIDR 命中证明符合这份策略，不证明运营商、国家或“住宅 IP”属性。

## 指定代理和目标

```powershell
python -m envscope audit --online --proxy http://127.0.0.1:7890
# 含凭据时，从自己设置的环境变量读取，避免写进命令历史
python -m envscope audit --online --proxy-env ENVSCOPE_PROXY_URL
python -m envscope audit --online --target https://example.com/
# 可选：密钥从 ENVSCOPE_CONTROLLER_SECRET 读取，只访问 loopback GET /configs
python -m envscope audit --online --controller http://127.0.0.1:9090
```

显式代理失败不会回退为另一条路径重试。HTTP 代理设置不会自动控制原生 STUN；跨路径差异必须结合实际 TUN/UDP 策略解释。没有 `--proxy` 时，curl 使用环境代理和系统路由，**不等于 Windows 浏览器的 WinINET 代理设置**。

curl 不载入用户 `.curlrc`，不执行远端脚本，不跟随 HTTP 重定向。控制接口不经过环境代理、不跟随重定向，不导出返回配置中的密钥。

## 系统与浏览器观测

一键检测在当前浏览器收集 HTTP 与 ICE 观测，然后自动传给本机 loopback 进程，合并系统检测结果。不会传给 EnvScope 外部服务器，不需要用户交换文件。浏览器与系统各自使用对应路径的 HTTP 对照。

高级 CLI 仍接受 `--browser <原始观测文件>`，重新评估地址和 ICE 类型。过期、未来、脱敏或未完成的观测不能通过。用户提供的观测未签名，不用于可信远程审计。

浏览器不申请麦克风/摄像头权限，不保证覆盖浏览器可使用的全部接口。网页不能强制双栈域名走某一地址族；IPv6 使用专用端点，结果保持独立。

## 报告、导入与变化比较

```powershell
python -m envscope import-switcher <已保存的last-check.txt>
python -m envscope report reports/audit.json --html reports/audit.html
python -m envscope diff reports/before.json reports/after.json
```

默认导出对地址使用本报告内别名，保留证据关系，隐藏常见用户目录名，删除 URL 凭据、查询参数和已识别的密钥字段。时区、语言、软件信息等仍可能识别环境，分享前需要自行复核。`diff` 只比较检查状态，不用不同报告的地址别名推断 IP 变化。

桌面偏好、对比密钥与最近 50 次脱敏历史保存在 `~/.envscope`。原始检测地址只在本次进程内存中评估；历史用本机随机密钥的 HMAC 比较实际观测的出口集合，密钥丢失后不跨密钥声称出口变化。历史页面不能用旧报告授权启动，切换仍会重新检测。出口变化本身不等于泄漏或账号风险。

`--include-sensitive` 可在本地保留原始地址。`reports/`、`artifacts/`、`.env`、`*.private.json` 均被 Git 忽略。静态 HTML 报告不加载外部资源、不包含可执行脚本。浏览器分享版与 CLI 诊断报告是两种有明确 `kind`/`tool` 的格式，不混用。
