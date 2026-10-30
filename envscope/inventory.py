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

from .observation_errors import check_command, error_evidence


def command_json(command, timeout=8):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    check_command(result)
    return json.loads(result.stdout)


def command_text(command, timeout=5):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                            env={**os.environ, 'LC_ALL': 'C'}, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    check_command(result)
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
    network = {"errors": {}}
    try:
        network['adapters'] = parse_macos_interfaces(command_text(['/sbin/ifconfig', '-a']))
        if not network['adapters']:
            raise ValueError('no recognized interfaces')
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        network['adapters'] = []
        network['errors']['adapters'] = error_evidence(exc, 'adapters')
    try:
        processes = command_text(["/bin/ps", "-A", "-o", "comm="])
        known = {"mihomo", "verge-mihomo", "flclashcore", "sing-box", "shadowrocket", "clashx", "surge", "wireguard", "tailscaled"}
        network["known_clients"] = sorted({Path(p.strip()).name for p in processes.splitlines() if Path(p.strip()).name.lower() in known})
    except (OSError, subprocess.TimeoutExpired) as exc:
        network["known_clients"] = []
        network['errors']['known_clients'] = error_evidence(exc, 'known_clients')
    try:
        dns = command_text(["/usr/sbin/scutil", "--dns"])
        network["dns"] = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", dns)))
    except (OSError, subprocess.TimeoutExpired) as exc:
        network['errors']['dns'] = error_evidence(exc, 'dns')
    try:
        route = command_text(["/sbin/route", "-n", "get", "default"])
        network["default_route"] = {k: v for k, v in re.findall(r"^\s*(gateway|interface):\s*(\S+)", route, re.M)}
        if not network['default_route'].get('interface'):
            raise ValueError('no recognized route')
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        network['errors']['routes'] = error_evidence(exc, 'routes')
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
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {'ipv6_off': None, **error_evidence(exc, 'ipv6_services')}
        with ThreadPoolExecutor(max_workers=4) as pool:
            network["ipv6_services"] = list(pool.map(inspect, services))
        failures = [row for row in network['ipv6_services'] if row.get('error')]
        if failures:
            # Keep every independent failure; the summary uses one bounded code.
            first = next((row for row in failures if row['error'] == 'permission_denied'), failures[0])
            network['errors']['ipv6_services'] = {'error': first['error'], 'operation': 'ipv6_services'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        network["ipv6_services"] = []
        network['errors']['ipv6_services'] = error_evidence(exc, 'ipv6_services')
    return network


def collect():
    result = {"platform": platform.system(), "release": platform.release(),
              "locale": locale.getlocale()[0], "timezone_names": list(time.tzname),
              "timezone_note": "原生名称仅作观测；Windows 时区 ID 与 IANA 标识不能直接比较。"}
    try:
        if platform.system() == "Windows":
            shell = shutil.which("powershell.exe")
            if not shell:
                raise FileNotFoundError("PowerShell unavailable")
            script = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$failures=@{}
function Read-Part($name, [scriptblock]$read) {
 try { & $read } catch {
   $denied=($_.Exception -is [System.UnauthorizedAccessException]) -or ([string]$_.CategoryInfo.Category -eq 'PermissionDenied')
   $missing=($_.Exception -is [System.Management.Automation.CommandNotFoundException])
   $failures[$name]=@{error=$(if($denied){'permission_denied'}elseif($missing){'tool_missing'}else{'unavailable'});operation=$name}
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
 ipv6_bindings=@(Read-Part 'ipv6_bindings' {Get-NetAdapterBinding -ComponentID ms_tcpip6 | Select-Object Name,Enabled})
 known_clients=@(Read-Part 'known_clients' {Get-Process | Where-Object {$_.ProcessName -in @('mihomo','verge-mihomo','FlClashCore','sing-box','wireguard','openvpn','tailscaled')} | Select-Object -ExpandProperty ProcessName -Unique})
 desktop_packages=@(Read-Part 'desktop_packages' {Get-AppxPackage -Name '*Claude*' | Select-Object Name,Version})
}
$v.errors=$failures
ConvertTo-Json -InputObject $v -Depth 6 -Compress
"""
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            result["network"] = command_json([shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
            if not isinstance(result['network'], dict):
                result.pop('network')
                raise ValueError('invalid inventory response')
            result["locale"] = result["network"].get("region_locale", result["locale"])
            result["client_language"] = {"value": result["network"].get("ui_language"), "source": "system-fallback"}
        elif platform.system() == "Darwin":
            result["network"] = macos_network()
            try:
                result["locale"] = command_text(["/usr/bin/defaults", "read", "-g", "AppleLocale"]).strip()
            except (OSError, subprocess.TimeoutExpired) as exc:
                result['network']['errors']['locale'] = error_evidence(exc, 'locale')
            try:
                from .mac_preferences import read_claude_language
                result['client_language']=read_claude_language()
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
                result['client_language']={'value':None,'source':'unavailable',**error_evidence(exc, 'client_language')}
                result['network']['errors']['language'] = error_evidence(exc, 'language')
            localtime = str(Path("/etc/localtime").resolve())
            if "/zoneinfo/" in localtime:
                result["timezone_iana"] = localtime.split("/zoneinfo/", 1)[1]
        else:
            result["network_error"] = "platform_network_adapter_not_implemented"
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        result['network_error'] = error_evidence(exc, 'inventory')
    if result['platform'] == 'Windows':
        from .wireguard import WireGuardReader
        result.setdefault('network', {})['wireguard'] = WireGuardReader().collect()
    return result
