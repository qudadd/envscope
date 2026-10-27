"""Discover configured proxies; never scan ports or rewrite system settings."""
import ipaddress
import os
from pathlib import Path
import platform
import re
import subprocess
from urllib.parse import urlsplit


def safe_local_proxy(value):
    """Only credential-free, literal loopback origins are auto-selectable."""
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 33 for c in value):
        return None
    try:
        p = urlsplit(value if "://" in value else "http://" + value)
        if (p.scheme not in ("http", "https", "socks5", "socks5h") or p.username is not None
                or p.password is not None or p.path not in ("", "/") or p.query or p.fragment
                or not p.port or not ipaddress.ip_address(p.hostname).is_loopback):
            return None
        return p.scheme + "://" + ("[" + p.hostname + "]" if ":" in p.hostname else p.hostname) + ":" + str(p.port)
    except (ValueError, TypeError):
        return None


def config_directories(home=None, platform_name=None, environ=None):
    home, system, env = Path(home) if home else Path.home(), platform_name or platform.system(), os.environ if environ is None else environ
    suffix = "io.github.clash-verge-rev.clash-verge-rev"
    if system == "Windows":
        return list(dict.fromkeys([Path(env.get("APPDATA") or home / "AppData/Roaming") / suffix,
                                   Path(env.get("LOCALAPPDATA") or home / "AppData/Local") / suffix]))
    if system == "Darwin":
        return [home / "Library/Application Support" / suffix]
    return []


def config_documents(home=None, platform_name=None, environ=None):
    for directory in config_directories(home, platform_name, environ):
        for name in ("clash-verge.yaml", "verge.yaml", "clash.yaml"):
            path = directory / name
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576:
                    yield path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue


def discover_proxies(home=None, platform_name=None, environ=None, system_reader=None):
    system, env = platform_name or platform.system(), os.environ if environ is None else environ
    found = {}
    def add(value, source):
        url = safe_local_proxy(value)
        if url:
            found.setdefault(url, {"url": url, "sources": [], "connection_verified": False})["sources"].append(source)
    for key in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        if env.get(key):
            add(env[key], "环境变量 " + key)
    try:
        if system_reader:
            value = system_reader()
        elif system == "Windows":
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
                value = winreg.QueryValueEx(key, "ProxyServer")[0] if enabled else ""
        elif system == "Darwin":
            r = subprocess.run(["/usr/sbin/scutil", "--proxy"], capture_output=True, text=True, timeout=3)
            value = r.stdout if r.returncode == 0 else ""
        else:
            value = ""
        if system == "Darwin":
            fields = dict(re.findall(r"^\s*(\w+)\s*:\s*(\S+)", value, re.M))
            for prefix, scheme in (("HTTP", "http"), ("HTTPS", "http"), ("SOCKS", "socks5")):
                if fields.get(prefix + "Enable") == "1":
                    add(scheme + "://" + fields.get(prefix + "Proxy", "") + ":" + fields.get(prefix + "Port", ""), "系统代理")
        else:
            for entry in value.split(";"):
                prefix, sep, address = entry.partition("=")
                add(("socks5://" if prefix == "socks" else "http://") + address if sep else entry, "系统代理")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    for document in config_documents(home, system, env):
        for key, scheme in (("mixed-port", "http"), ("port", "http"), ("socks-port", "socks5")):
            match = re.search(r"^" + key + r":\s*(\d+)\s*(?:#.*)?$", document, re.M)
            if match:
                add(scheme + "://127.0.0.1:" + match[1], "代理客户端配置")
    return list(found.values())
