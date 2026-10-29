"""Read-only, bounded platform inventory. Interface presence is not route proof."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import locale
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time


def command_json(command, timeout=8):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode or len(result.stdout) > 262144:
        raise OSError("inventory command failed")
    return json.loads(result.stdout)


def command_text(command, timeout=5):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode or len(result.stdout) > 262144:
        raise OSError("inventory command failed")
    return result.stdout


def parse_macos_interfaces(text):
    interfaces, current = [], None
    for line in text.splitlines():
        match = re.match(r"^([a-zA-Z0-9._-]+):\s+flags=.*<([^>]*)>", line)
        if match:
            current = {"name": match[1], "flags": match[2].split(","), "addresses": []}
            interfaces.append(current)
        elif current is not None:
            address = re.match(r"\s+inet(6?)\s+([^\s]+)", line)
            if address:
                current["addresses"].append({"family": 6 if address[1] else 4, "ip": address[2]})
    return interfaces


def macos_network():
    network = {"adapters": parse_macos_interfaces(command_text(["/sbin/ifconfig", "-a"]))}
    try:
        processes = command_text(["/bin/ps", "-A", "-o", "comm="])
        known = {"mihomo", "verge-mihomo", "sing-box", "shadowrocket", "clashx", "surge", "wireguard", "tailscaled"}
        network["known_clients"] = sorted({Path(p.strip()).name for p in processes.splitlines() if Path(p.strip()).name.lower() in known})
    except (OSError, subprocess.TimeoutExpired):
        network["known_clients"] = []
    try:
        dns = command_text(["/usr/sbin/scutil", "--dns"])
        network["dns"] = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", dns)))
    except (OSError, subprocess.TimeoutExpired):
        network["dns_error"] = "unavailable"
    try:
        route = command_text(["/sbin/route", "-n", "get", "default"])
        network["default_route"] = {k: v for k, v in re.findall(r"^\s*(gateway|interface):\s*(\S+)", route, re.M)}
    except (OSError, subprocess.TimeoutExpired):
        network["default_route_error"] = "unavailable"
    try:
        order = command_text(["/usr/sbin/networksetup", "-listnetworkserviceorder"])
        active = {a["name"] for a in network["adapters"] if "UP" in a["flags"] and a["name"].startswith("en")
                  and any(v["family"] == 4 for v in a["addresses"])}
        pairs = re.findall(r"^\(\d+\) ([^\n]+)\n\(Hardware Port: [^\n]*, Device: ([^)]+)\)", order, re.M)
        services = [name.strip() for name, device in pairs if device.strip() in active][:8]
        def inspect(name):
            try:
                info = command_text(["/usr/sbin/networksetup", "-getinfo", name], timeout=3)
                return {"ipv6_off": bool(re.search(r"^IPv6:\s*Off\s*$", info, re.M))}
            except (OSError, subprocess.TimeoutExpired):
                return {"ipv6_off": None}
        with ThreadPoolExecutor(max_workers=4) as pool:
            network["ipv6_services"] = list(pool.map(inspect, services))
    except (OSError, subprocess.TimeoutExpired):
        network["ipv6_services"] = []
    return network


def collect():
    result = {"platform": platform.system(), "release": platform.release(),
              "locale": locale.getlocale()[0], "timezone_names": list(time.tzname),
              "timezone_note": "原生名称仅作观测；Windows 时区 ID 与 IANA 标识不能直接比较。"}
    try:
        if platform.system() == "Windows":
            shell = shutil.which("powershell.exe")
            if not shell:
                raise OSError("PowerShell unavailable")
            script = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$failures=@{}
function Read-Part($name, [scriptblock]$read) {
 try { & $read } catch {
   $denied=($_.Exception -is [System.UnauthorizedAccessException]) -or ([string]$_.CategoryInfo.Category -eq 'PermissionDenied')
   $failures[$name]=@{error=$(if($denied){'permission_denied'}else{'unavailable'})}
 }
}
$v=@{
 adapters=@(Read-Part 'adapters' {Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,ifIndex})
 addresses=@(Read-Part 'addresses' {Get-NetIPAddress | Select-Object InterfaceIndex,AddressFamily,IPAddress,PrefixLength})
 dns=@(Read-Part 'dns' {Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses})
 default_routes=@(Read-Part 'routes' {Get-NetRoute | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')} | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric})
 timezone_id=(Read-Part 'timezone' {(Get-TimeZone).Id})
 ui_language=(Read-Part 'language' {(Get-UICulture).Name})
 region_locale=(Read-Part 'locale' {(Get-Culture).Name})
 ipv6_bindings=@(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Select-Object Name,Enabled)
 known_clients=@(Get-Process -Name 'mihomo','verge-mihomo','sing-box','wireguard','openvpn','tailscaled' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
 desktop_packages=@(Get-AppxPackage -Name '*Claude*' -ErrorAction SilentlyContinue | Select-Object Name,Version)
}
$v.errors=$failures
ConvertTo-Json -InputObject $v -Depth 6 -Compress
"""
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            result["network"] = command_json([shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
            result["locale"] = result["network"].get("region_locale", result["locale"])
            result["client_language"] = {"value": result["network"].get("ui_language"), "source": "system-fallback"}
        elif platform.system() == "Darwin":
            result["network"] = macos_network()
            try:
                result["locale"] = command_text(["/usr/bin/defaults", "read", "-g", "AppleLocale"]).strip()
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                from .mac_preferences import read_claude_language
                result['client_language']=read_claude_language()
            except (OSError,ValueError,RuntimeError):
                result['client_language']={'value':None,'source':'unavailable','error':'application-preference-unavailable'}
            localtime = str(Path("/etc/localtime").resolve())
            if "/zoneinfo/" in localtime:
                result["timezone_iana"] = localtime.split("/zoneinfo/", 1)[1]
        else:
            result["network_error"] = "platform_network_adapter_not_implemented"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        result["network_error"] = "inventory_unavailable_or_deadline"
    if result['platform'] == 'Windows':
        from .wireguard import WireGuardReader
        result.setdefault('network', {})['wireguard'] = WireGuardReader().collect()
    return result
