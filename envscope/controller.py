"""Read only a loopback Clash-compatible runtime API; no remote management."""
import ipaddress
import json
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler, Request

from .model import Finding, Status


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_controller(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or not parsed.hostname):
        raise ValueError("controller must be an HTTP loopback origin")
    address = ipaddress.ip_address(parsed.hostname)
    if not address.is_loopback or not parsed.port:
        raise ValueError("controller must use a literal loopback IP and explicit port")
    return url.rstrip("/")


def inspect_controller(url, secret=None):
    origin = validate_controller(url)
    headers = {"Accept": "application/json"}
    if secret:
        if any(ord(c) < 32 for c in secret):
            raise ValueError("invalid controller secret")
        headers["Authorization"] = "Bearer " + secret
    # Avoid sending controller credentials to an environment HTTP proxy or redirect.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    try:
        with opener.open(Request(origin + "/configs", headers=headers), timeout=3) as response:
            data = response.read(65537)
        if len(data) > 65536:
            raise ValueError("oversized controller response")
        config = json.loads(data)
        if not isinstance(config, dict) or config.get("mode") not in ("rule", "global", "direct"):
            raise ValueError("unrecognized runtime config")
        tun = config.get("tun", {})
        evidence = [{"mode": config["mode"], "tun_enabled": tun.get("enable") if isinstance(tun, dict) else None,
                     "source": "loopback-runtime-config"}]
        return Finding("runtime.config", "代理内核运行配置", Status.WARN if config["mode"] == "direct" else Status.PASS,
                       "内核报告直连模式，请核对目标路径" if config["mode"] == "direct" else "已读取运行配置；不代表流量确已接管",
                       "loopback-controller", evidence, ["只读取 GET /configs；不修改规则、切换节点或读取密钥。",
                                                          "运行配置不能替代目标路由、进程套接字或抓包验证。"])
    except (OSError, ValueError):
        return Finding("runtime.config", "代理内核运行配置", Status.UNKNOWN, "控制接口不可用、未授权或响应无效",
                       "loopback-controller", limitations=["没有回退为读取配置文件后判通过。"])
