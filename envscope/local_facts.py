"""Selected local configuration facts; credentials and profile content never leave this module."""
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
from urllib.parse import urlsplit

from .discovery import config_documents, discover_proxies
from .accounts import AccountManager, AccountError
from .transport import display_url
from .config_files import inspect_text

TARGETS = ("claude.ai", "api.anthropic.com")


def bypass_matches(value):
    entries = [s.strip() for s in re.split(r"[,;\s]+", str(value)) if s.strip()][:128]
    matches = set()
    for pattern in entries:
        for host in TARGETS:
            candidate = pattern.lower().split(":", 1)[0].lstrip(".")
            if pattern == "*" or fnmatch.fnmatchcase(host, candidate) or host.endswith("." + candidate):
                matches.add(host)
    return {"entry_count": len(entries), "target_matches": sorted(matches), "all_hosts": "*" in entries}


def proxy_endpoint(value):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
        return None
    try:
        parsed = urlsplit(value if "://" in value else "http://" + value)
        if parsed.scheme not in ("http", "https", "socks5", "socks5h") or not parsed.hostname:
            return None
        _ = parsed.port
        return display_url(value if "://" in value else "http://" + value)
    except ValueError:
        return None


def read_system_proxy(system=None, reader=None):
    system = system or platform.system()
    try:
        if reader:
            raw = reader()
        elif system == "Windows":
            import winreg
            raw = {}
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"):
                    try:
                        raw[name] = winreg.QueryValueEx(key, name)[0]
                    except OSError:
                        pass
        elif system == "Darwin":
            r = subprocess.run(["/usr/sbin/scutil", "--proxy"], capture_output=True, text=True, timeout=3)
            if r.returncode or len(r.stdout) > 65536:
                raise OSError("unavailable")
            raw = r.stdout
        else:
            return {"available": False}
        endpoints = []
        if system == "Windows" and isinstance(raw, dict):
            if raw.get("ProxyEnable") == 1:
                for entry in str(raw.get("ProxyServer", "")).split(";"):
                    kind, sep, value = entry.partition("=")
                    url = proxy_endpoint(("socks5://" if kind == "socks" else "http://") + value if sep else entry)
                    if url:
                        endpoints.append(url)
            return {"available": True, "enabled": raw.get("ProxyEnable") == 1, "endpoints": sorted(set(endpoints)),
                    "pac_configured": bool(raw.get("AutoConfigURL")), "auto_detect": raw.get("AutoDetect") == 1 if "AutoDetect" in raw else None,
                    "bypass": bypass_matches(raw.get("ProxyOverride", ""))}
        if system == "Darwin" and isinstance(raw, str):
            fields = dict(re.findall(r"^\s*(\w+)\s*:\s*(\S+)", raw, re.M))
            for prefix, scheme in (("HTTP", "http"), ("HTTPS", "http"), ("SOCKS", "socks5")):
                if fields.get(prefix + "Enable") == "1":
                    url = proxy_endpoint(scheme + "://" + fields.get(prefix + "Proxy", "") + ":" + fields.get(prefix + "Port", ""))
                    if url:
                        endpoints.append(url)
            exceptions = re.search(r"ExceptionsList\s*:\s*<array>\s*\{([^}]+)", raw, re.S)
            patterns = re.findall(r"\d+\s*:\s*(\S+)", exceptions[1]) if exceptions else []
            return {"available": True, "enabled": bool(endpoints), "endpoints": sorted(set(endpoints)),
                    "pac_configured": fields.get("ProxyAutoConfigEnable") == "1", "auto_detect": fields.get("ProxyAutoDiscoveryEnable") == "1",
                    "bypass": bypass_matches(";".join(patterns))}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return {"available": False}


def proxy_layers(environ=None, system_proxy=None):
    env = os.environ if environ is None else environ
    urls, invalid = [], 0
    for upper, lower in (("HTTPS_PROXY", "https_proxy"), ("HTTP_PROXY", "http_proxy"), ("ALL_PROXY", "all_proxy")):
        value = env.get(lower) or env.get(upper)
        if value:
            url = proxy_endpoint(value)
            if url:
                urls.append(url)
            else:
                invalid += 1
    return {"system": read_system_proxy() if system_proxy is None else system_proxy, "environment": sorted(set(urls)),
            "invalid_environment_count": invalid, "environment_bypass": bypass_matches(env.get("no_proxy") or env.get("NO_PROXY", ""))}


def probe_listeners(proxies, connector=socket.create_connection):
    found = []
    for item in proxies[:4]:
        try:
            parsed = urlsplit(item["url"])
            if not ipaddress.ip_address(parsed.hostname).is_loopback or not parsed.port:
                continue
            with connector((parsed.hostname, parsed.port), timeout=0.35):
                opened = True
        except (OSError, ValueError, TypeError, KeyError):
            opened = False
        found.append({"endpoint": display_url(item.get("url", "")), "tcp_accepts": opened})
    return found


def hosts_overrides(path):
    try:
        if path.stat().st_size > 1048576:
            return {"readable": False, "error": "hosts_too_large"}
        overrides = []
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            tokens = line.split("#", 1)[0].split()
            if len(tokens) < 2:
                continue
            for host in tokens[1:]:
                if host.lower().rstrip(".") in TARGETS:
                    try:
                        ip = str(ipaddress.ip_address(tokens[0]))
                    except ValueError:
                        continue
                    overrides.append({"host": host.lower().rstrip("."), "ip": ip})
        return {"readable": True, "overrides": overrides[:32]}
    except OSError:
        return {"readable": False}


def config_shape(path):
    try:
        if not path.exists():
            return {"exists": False}
        if path.is_symlink() or path.stat().st_size > 1048576:
            return {"exists": True, "valid": False, "error": "unsupported_size_or_symlink"}
        return {"exists": True, **inspect_text(path.read_text(encoding="utf-8-sig"))}
    except OSError:
        return {"exists": True, "valid": None, "error": "unreadable"}
    except UnicodeError:
        return {"exists": True, "valid": False, "error": "encoding", "explanation": "文件不是有效的 UTF-8 文本"}


def account_markers(state, profile):
    try:
        return AccountManager(state, profile).inspect_integrity()
    except AccountError as error:
        if isinstance(error.__cause__, OSError):
            return {"valid": None, "error": "unavailable"}
        return {"valid": False, "error": "invalid_or_unsafe_account_structure"}
    except OSError:
        return {"valid": None, "error": "unavailable"}


def cli_facts(home, environ):
    # Only the user settings scope is inspected. Project/managed scopes may override it.
    config = config_shape(home / ".claude/settings.json")
    effective = dict(environ)
    if config.get("valid") is True:
        try:
            data = json.loads((home / ".claude/settings.json").read_text(encoding="utf-8-sig"))
            effective.update(data.get("env", {}))
        except (OSError, ValueError):
            pass
    environ = effective
    files = set()
    for directory in environ.get("PATH", "").split(os.pathsep)[:64]:
        if not directory or directory.startswith(("\\\\", "//")):
            continue
        for name in ("claude", "claude.exe", "claude.cmd"):
            path = Path(directory) / name
            try:
                if path.is_file():
                    files.add(str(path.resolve().with_suffix("")))
            except OSError:
                pass
    # Export only the count, origin classes and booleans, never credentials.
    classes = sorted({"npm" if re.search(r"npm|node_modules", name, re.I) else "bun" if ".bun" in name else "native-or-other" for name in files})
    base = environ.get("ANTHROPIC_BASE_URL", "")
    try:
        parsed = urlsplit(base) if isinstance(base, str) else None
        if parsed:
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("invalid port")
    except ValueError:
        parsed = None
    url_valid = bool(not base or parsed and len(base) <= 2048 and not any(c.isspace() or ord(c) < 32 for c in base)
                     and parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment)
    try:
        local = bool(parsed and parsed.hostname and (parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback))
    except ValueError:
        local = False
    proxy_value = next((environ.get(k) for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY") if environ.get(k)), "")
    proxy = proxy_endpoint(proxy_value) if proxy_value else None
    extra_ca = environ.get("NODE_EXTRA_CA_CERTS")
    try:
        ca_exists = Path(extra_ca).is_file() if extra_ca else None
    except (OSError, ValueError):
        ca_exists = None
    return {"installation_count": len(files), "origins": classes, "config": config,
            "api_key_present": bool(environ.get("ANTHROPIC_API_KEY")), "auth_token_present": bool(environ.get("ANTHROPIC_AUTH_TOKEN")),
            "custom_endpoint": bool(base), "endpoint_valid": url_valid, "endpoint_https_or_local": not base or bool(parsed and parsed.scheme == "https") or local,
            "bedrock": environ.get("CLAUDE_CODE_USE_BEDROCK") == "1", "vertex": environ.get("CLAUDE_CODE_USE_VERTEX") == "1",
            "foundry": environ.get("CLAUDE_CODE_USE_FOUNDRY") == "1",
            "proxy_configured": bool(proxy_value), "proxy_valid": not proxy_value or bool(proxy),
            "proxy_scheme": urlsplit(proxy).scheme if proxy else None,
            "proxy_bypass": bypass_matches(environ.get("no_proxy") or environ.get("NO_PROXY", "")),
            "tls_verification_disabled": environ.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0",
            "extra_ca_configured": bool(extra_ca), "extra_ca_exists": ca_exists,
            "settings_scope": "current-process-and-user-settings"}


def local_snapshot(inventory, home=None, environ=None, system=None, system_reader=None, listener=probe_listeners, hosts_path=None):
    home = Path(home) if home else Path.home()
    env, system = os.environ if environ is None else environ, system or platform.system()
    profile = (Path(env.get("APPDATA") or home / "AppData/Roaming") / "Claude" if system == "Windows" else home / "Library/Application Support/Claude")
    hostfile = hosts_path or (Path(env.get("WINDIR", "C:/Windows")) / "System32/drivers/etc/hosts" if system == "Windows" else Path("/etc/hosts"))
    packages = inventory.get("network", {}).get("desktop_packages", [])
    installed = bool(packages)
    if system == "Windows":
        installed = installed or any(p.is_file() for p in (home / "AppData/Local/Programs/Claude/Claude.exe", home / "AppData/Local/AnthropicClaude/Claude.exe"))
    elif system == "Darwin":
        installed = any((p / "Contents/Info.plist").is_file() for p in (Path("/Applications/Claude.app"), home / "Applications/Claude.app"))
    current = profile
    for _ in range(8):
        if current.exists() or current.parent == current:
            break
        current = current.parent
    try:
        disk = shutil.disk_usage(current)
        storage = {"free_bytes": disk.free, "total_bytes": disk.total}
    except OSError:
        storage = {}
    controller = {"found": False}
    for doc in config_documents(home, system, env):
        match = re.search(r"^external-controller:\s*[\"']?([^\s\"']+)", doc, re.M)
        if match:
            try:
                bind = urlsplit("http://" + match[1]).hostname
                loopback_bind = ipaddress.ip_address(bind).is_loopback
            except ValueError:
                loopback_bind = None
            controller = {"found": True, "wildcard_bind": match[1].startswith(("0.0.0.0:", "[::]:", "*:")), "loopback_bind": loopback_bind,
                          "secret_configured": bool(re.search(r"^secret:\s*[\"']?[^\s\"'#]+", doc, re.M))}
    return {"proxy": proxy_layers(env, read_system_proxy(system, system_reader)),
            "listeners": listener(discover_proxies(home, system, env, system_reader=system_reader)),
            "hosts": hosts_overrides(Path(hostfile)), "installed": installed,
            "profile_exists": profile.is_dir(), "desktop_config": config_shape(profile / "claude_desktop_config.json"),
            "cli": cli_facts(home, env), "storage": storage, "account": account_markers(home / ".claude-switcher", profile),
            "controller": controller}
