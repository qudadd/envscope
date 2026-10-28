"""Bounded native information panels, independent of the optional legacy install."""
import json
import platform
import shutil
import subprocess
from pathlib import Path


def cli_information(home, which=shutil.which):
    entries = [(name, which(name)) for name in ("claude", "claude.exe", "claude.cmd", "node", "npm")]
    rows = [{"label": name, "value": path or "当前进程 PATH 中未找到"} for name, path in entries]
    rows.append({"label": "Code 配置目录", "value": "已存在" if (Path(home) / ".claude").is_dir() else "尚未发现；首次使用前可能尚未创建"})
    return {"state": "completed", "title": "Claude Code 安装信息", "rows": rows,
            "installations": dict(entries), "config_exists": (Path(home) / ".claude").is_dir(),
            "note": "仅检查当前进程的命令搜索路径，不运行找到的程序。刚安装后请重开 EnvScope 和常用终端；用 claude doctor 核对实际会话。"}


def _read_json(command):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="strict", timeout=12,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode or len(result.stdout) > 262144:
        raise ValueError("device information unavailable")
    return json.loads(result.stdout.lstrip("\ufeff"))


def device_information(system=None, reader=None):
    system = system or platform.system()
    reader = reader or _read_json
    rows = [{"label": "操作系统", "value": system + " " + platform.release()},
            {"label": "处理器架构", "value": platform.machine() or "尚未取得"}]
    note = "设备资料仅供本机排障，不用于判断账号风险。未读取序列号或登录凭据。"
    try:
        if system == "Windows":
            code = r"""[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference='Stop'
@{gpu=@(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion);machine=(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model);font_count=@(Get-ChildItem -LiteralPath ($env:WINDIR+'\Fonts') -File).Count} | ConvertTo-Json -Depth 5 -Compress"""
            data = reader(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code])
            machine = data.get("machine") or {}
            rows += [{"label": "制造商", "value": machine.get("Manufacturer") or "尚未取得"},
                     {"label": "设备型号", "value": machine.get("Model") or "尚未取得"}]
            for gpu in data.get("gpu", []):
                rows.append({"label": "显卡 / 驱动", "value": " / ".join(str(gpu[k]) for k in ("Name", "DriverVersion") if gpu.get(k)) or "尚未取得"})
            if type(data.get("font_count")) is int:
                rows.append({"label": "系统字体文件数", "value": str(data["font_count"])})
        elif system == "Darwin":
            # SPDisplaysDataType avoids the hardware serial-number inventory.
            data = reader(["/usr/sbin/system_profiler", "SPDisplaysDataType", "-json", "-detailLevel", "mini", "-timeout", "8"])
            for gpu in data.get("SPDisplaysDataType", []):
                rows.append({"label": "图形设备", "value": str(gpu.get("sppci_model") or gpu.get("_name") or "尚未取得")})
        else:
            return {"state": "partial", "title": "设备信息", "rows": rows, "note": note + " 当前系统仅显示基本资料。"}
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, subprocess.TimeoutExpired):
        return {"state": "partial", "title": "设备信息", "rows": rows,
                "note": note + " 显卡或型号未能在期限内读取，可稍后重试；不影响其他功能。"}
    return {"state": "completed", "title": "设备信息", "rows": rows, "note": note}
