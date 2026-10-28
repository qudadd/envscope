"""Scoped help only after an actual OS permission denial, never blanket elevation."""
import os
from pathlib import Path
import platform
import subprocess

from .assessment import denied


def permission_help(report, params, home, profile, confirmed=False, runner=subprocess.Popen, system=None):
    if set(params) != {"report_id", "finding_id"} or not report or params["report_id"] != report.get("report_id"):
        return {"state": "retest_required", "reason": "先完成本轮检测，再处理本次明确拒绝的权限。"}
    finding = next((f for f in report.get("findings", []) if f["id"] == params["finding_id"]), None)
    if not finding or not denied(finding.get("evidence", [])):
        raise ValueError("这项没有明确的权限拒绝证据，不申请额外权限")
    system = system or platform.system()
    scopes = {"extra.hosts": ("读取 hosts 中与 Claude 有关的记录", Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/drivers/etc/hosts"),
              "extra.config": ("读取 Claude / Code 用户配置的格式", profile),
              "target.config": ("读取所选 Claude / Code 用户配置的格式", home / '.claude' if report.get('usage') == 'cli' else profile),
              "extra.cli_env": ("读取 Code 用户配置的格式与环境项存在性", home / ".claude"),
              "extra.proxy_layers": ("读取当前用户的系统代理设置", None)}
    if finding["id"] not in scopes:
        return {"state": "unavailable", "reason": "系统拒绝了读取。请根据证据检查应用或文件的访问权限，再检测；当前没有可自动打开的授权入口。"}
    label, path = scopes[finding["id"]]
    reason = label + "。不会修改该配置或导出密钥；将打开系统入口，由你授予必要的读取权限，然后重新检测。"
    if confirmed is not True:
        return {"state": "confirmation_required", "reason": reason}
    if system == "Darwin":
        command = ["/usr/bin/open", "x-apple.systempreferences:com.apple.preference.security?Privacy_FilesAndFolders"]
        instruction = "在隐私与安全性中检查 EnvScope 的文件与文件夹权限；仅在受保护资料仍被拒绝时评估完全磁盘访问。授权后重新打开软件并检测。"
    elif system == "Windows":
        command = [str(Path(os.environ.get("WINDIR", "C:/Windows")) / "explorer.exe")]
        command += ["/select,", str(path)] if path else ["ms-settings:network-proxy"]
        instruction = "Windows 文件读取权限需在文件或文件夹的属性 → 安全中核对。请让所属用户拥有读取权限；组织策略限制请联系管理员。完成后重新检测。"
    else:
        return {"state": "unavailable", "reason": "当前仅支持 Windows 与 macOS。"}
    runner(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return {"state": "opened", "reason": instruction, "permission_granted": False}
