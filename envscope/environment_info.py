"""Bounded native information panels, independent of the optional legacy install."""
import json
import platform
import shutil
import subprocess
import os
from pathlib import Path


def cli_information(home, which=shutil.which, path=None):
    entries = [(name, which(name)) for name in ("claude", "claude.exe", "claude.cmd", "node", "npm")]
    rows = [{"label": name, "value": path or "当前进程 PATH 中未找到"} for name, path in entries]
    rows.append({"label": "Code 配置目录", "value": "已存在" if (Path(home) / ".claude").is_dir() else "尚未发现；首次使用前可能尚未创建"})
    from .cli_inventory import installation_details
    detail = installation_details(home, path=path)
    rows.extend(detail['rows'])
    return {"state": "completed", "title": "Claude Code 安装信息", "rows": rows,
            "details":detail,
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
@{gpu=@(Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution);machine=(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,HypervisorPresent);font_count=@(Get-ChildItem -LiteralPath ($env:WINDIR+'\Fonts') -File).Count} | ConvertTo-Json -Depth 5 -Compress"""
            data = reader(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code])
            machine = data.get("machine") or {}
            rows += [{"label": "制造商", "value": machine.get("Manufacturer") or "尚未取得"},
                     {"label": "设备型号", "value": machine.get("Model") or "尚未取得"}]
            for gpu in data.get("gpu", []):
                rows.append({"label": "显卡 / 驱动", "value": " / ".join(str(gpu[k]) for k in ("Name", "DriverVersion") if gpu.get(k)) or "尚未取得"})
                if gpu.get('CurrentHorizontalResolution') and gpu.get('CurrentVerticalResolution'):
                    rows.append({'label':'显示分辨率','value':str(gpu['CurrentHorizontalResolution'])+' × '+str(gpu['CurrentVerticalResolution'])})
            if type(machine.get('HypervisorPresent')) is bool:
                rows.append({'label':'虚拟化组件线索','value':'系统报告虚拟化组件存在；宿主 Hyper-V 也会出现，不能据此判定虚拟机' if machine['HypervisorPresent'] else '系统未报告虚拟化组件；不证明没有虚拟化'})
            if type(data.get("font_count")) is int:
                rows.append({"label": "系统字体文件数", "value": str(data["font_count"])})
        elif system == "Darwin":
            # SPDisplaysDataType avoids the hardware serial-number inventory.
            data = reader(["/usr/sbin/system_profiler", "SPDisplaysDataType", "-json", "-detailLevel", "mini", "-timeout", "8"])
            for gpu in data.get("SPDisplaysDataType", []):
                rows.append({"label": "图形设备", "value": str(gpu.get("sppci_model") or gpu.get("_name") or "尚未取得")})
                for display in gpu.get('spdisplays_ndrvs',[]):
                    resolution = display.get('_spdisplays_resolution') or display.get('spdisplays_resolution')
                    if isinstance(resolution,str):
                        rows.append({'label':'显示分辨率','value':resolution})
            try:
                virtual = reader(['/usr/sbin/sysctl','-n','kern.hv_vmm_present'])
                rows.append({'label':'虚拟机线索','value':{0:'内核未报告虚拟机标记；不证明物理设备',1:'内核报告虚拟机标记'}.get(virtual if type(virtual) is int else -1,'本机未提供此标记')})
            except (OSError, ValueError, subprocess.TimeoutExpired):
                rows.append({'label':'虚拟机线索','value':'本机未提供此标记'})
            count = sum(1 for base in (Path('/Library/Fonts'),Path('/System/Library/Fonts'),Path.home()/'Library/Fonts')
                        if base.is_dir() for p in base.iterdir() if p.is_file() and not p.is_symlink())
            rows.append({'label':'所列目录字体文件数','value':str(count)+'（仅目录第一层，不代表全部字体）'})
        else:
            return {"state": "partial", "title": "设备信息", "rows": rows, "note": note + " 当前系统仅显示基本资料。"}
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, subprocess.TimeoutExpired):
        return {"state": "partial", "title": "设备信息", "rows": rows,
                "note": note + " 显卡或型号未能在期限内读取，可稍后重试；不影响其他功能。"}
    return {"state": "completed", "title": "设备信息", "rows": rows, "note": note}


def device_finding(info):
    from .model import Finding, Status
    return Finding('device.environment','设备与显示环境',Status.PASS if info.get('state')=='completed' else Status.UNKNOWN,
                   '已读取所列设备资料；仅作兼容性记录' if info.get('state')=='completed' else '部分设备资料没有取得',
                   'native-read-only-device-information', info.get('rows',[]),
                   [info.get('note',''), '字体、GPU 或虚拟化标记不用于判断服务端风控；没有读取序列号。'],
                   '有显示或渲染问题时核对系统驱动和浏览器设置；无需为获得通过更改设备特征。')
