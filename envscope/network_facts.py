"""Bounded DNS and OS-selected routes. This is not per-process packet tracing."""
import base64
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time

from .observation_errors import check_command, error_evidence

HOSTS = ("claude.ai", "api.anthropic.com")


def resolve_host(host, resolver=socket.getaddrinfo):
    started = time.monotonic()
    try:
        records = resolver(host, None, type=socket.SOCK_STREAM)
        values = sorted({str(ipaddress.ip_address(r[4][0].split("%", 1)[0])) for r in records})
        return {"host": host, "addresses": values[:32], "elapsed_ms": round((time.monotonic() - started) * 1000),
                "complete": len(values) <= 32}
    except (OSError, ValueError, IndexError):
        return {"host": host, "addresses": [], "error": "resolution_unavailable"}


def parse_mac_route(text, destination):
    values = dict(re.findall(r"^\s*(interface|gateway|destination|mask|flags):\s*([^\n]+)", text, re.M))
    if not values.get("interface") or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", values["interface"].strip()):
        return {'destination': destination, **error_evidence(ValueError(), 'routes')}
    return {"destination": destination, "interface": values["interface"].strip(),
            "next_hop": values.get("gateway", "").strip(), "flags": values.get("flags", "").strip()}


def lookup_routes(addresses, system=None, runner=subprocess.run):
    addresses = [str(ipaddress.ip_address(ip)) for ip in addresses][:4]
    system = system or platform.system()
    if not addresses:
        return []
    if system == "Windows":
        script = r"""
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$ips=ConvertFrom-Json 'IP_LIST'
$items=@(foreach($ip in $ips){
 try {
  $best=@(Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop)
  $route=$best|Where-Object {$_.PSObject.Properties['DestinationPrefix']}|Select-Object -First 1
  $source=$best|Where-Object {$_.PSObject.Properties['IPAddress']}|Select-Object -First 1
  if(-not $route){throw 'no route'}
  @{destination=$ip;interface_index=$route.InterfaceIndex;interface=$route.InterfaceAlias;prefix=$route.DestinationPrefix;next_hop=$route.NextHop;source_ip=$source.IPAddress}
 } catch {
  $denied=($_.Exception -is [System.UnauthorizedAccessException]) -or ([string]$_.CategoryInfo.Category -eq 'PermissionDenied')
  $missing=($_.Exception -is [System.Management.Automation.CommandNotFoundException])
  @{destination=$ip;error=$(if($denied){'permission_denied'}elseif($missing){'tool_missing'}else{'unavailable'})}
 }
})
ConvertTo-Json -InputObject $items -Depth 4 -Compress
""".replace("IP_LIST", json.dumps(addresses))
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=7,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            check_command(result, 16384)
            value = json.loads(result.stdout)
            if not isinstance(value, list):
                raise ValueError("invalid routes")
            # Never accept a script response for a destination we did not ask for.
            rows = [r for r in value if isinstance(r, dict) and r.get('destination') in addresses]
            if len(rows) != len(addresses) or len({r['destination'] for r in rows}) != len(addresses):
                raise ValueError('incomplete routes')
            return [{k: r[k] for k in ('destination', 'interface_index', 'interface', 'prefix', 'next_hop', 'source_ip', 'error') if k in r} for r in rows]
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return [{'destination': ip, **error_evidence(exc, 'routes')} for ip in addresses]
    if system == "Darwin":
        def one(ip):
            command = ["/sbin/route", "-n", "get", "-inet6" if ":" in ip else "-inet", ip]
            try:
                result = runner(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3)
                check_command(result, 16384)
                return parse_mac_route(result.stdout, ip)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {'destination': ip, **error_evidence(exc, 'routes')}
        with ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(one, addresses))
    return [{"destination": ip, "error": "unsupported_platform"} for ip in addresses]


def collect_facts(resolver=socket.getaddrinfo, router=lookup_routes):
    with ThreadPoolExecutor(max_workers=2) as pool:
        dns = list(pool.map(lambda host: resolve_host(host, resolver), HOSTS))
    selected = []
    for item in dns:
        for family in (4, 6):
            address = next((ip for ip in item["addresses"] if ipaddress.ip_address(ip).version == family), None)
            if address and address not in selected:
                selected.append(address)
    return {"dns": dns, "routes": router(selected), "route_scope": "one-address-per-host-and-family"}


def bounded_facts(timeout=16):
    try:
        with tempfile.TemporaryDirectory(prefix="envscope-network-") as directory:
            output = Path(directory) / "facts.private.json"
            command = [sys.executable, "--network-worker"] if getattr(sys, "frozen", False) else [sys.executable, "-m", "envscope.network_facts"]
            command.append(str(output))
            result = subprocess.run(command, capture_output=True, timeout=timeout,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode == 0 and output.is_file() and output.stat().st_size <= 32768:
                value = json.loads(output.read_text(encoding="utf-8"))
                if isinstance(value, dict) and isinstance(value.get("dns"), list) and isinstance(value.get("routes"), list):
                    return value
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return {"dns": [], "routes": [], "error": "network_observation_deadline_or_unavailable"}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 2 and args[0] == "--offline":
        Path(args[1]).write_text(json.dumps({"dns": [], "routes": [], "mode": "offline"}), encoding="utf-8")
        return
    if len(args) != 1:
        raise SystemExit("one output file required")
    Path(args[0]).write_text(json.dumps(collect_facts()), encoding="utf-8")


if __name__ == "__main__":
    main()
