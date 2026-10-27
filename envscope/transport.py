"""Bounded curl transport; explicit proxies never retry over another path."""
from dataclasses import dataclass
import json
import os
import shutil
import subprocess
from urllib.parse import urlsplit, urlunsplit

MAX_BODY = 131072
MARKER = "\nENVSCOPE_CURL_METADATA:"


def display_url(url):
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = "[" + host + "]"
        authority = host + ((":" + str(parts.port)) if parts.port else "")
        return urlunsplit((parts.scheme, authority, parts.path, "", ""))
    except ValueError:
        return "invalid-url"


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 32 or c in '\\"' for c in url):
        raise ValueError("invalid URL")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
        raise ValueError("only credential-free HTTP(S) URLs are supported")
    if parts.fragment:
        raise ValueError("URL fragments are not supported")
    _ = parts.port
    return url


@dataclass
class Response:
    status: int = 0
    body: str = ""
    content_type: str = ""
    error: str = ""


class CurlTransport:
    def __init__(self, proxy=None, timeout=4, runner=subprocess.run):
        self.timeout = timeout
        self.runner = runner
        self.executable = shutil.which("curl.exe" if os.name == "nt" else "curl")
        self.proxy = proxy
        if proxy is not None and not isinstance(proxy, str):
            raise ValueError("proxy URL must be a string")
        if proxy:
            if len(proxy) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in proxy):
                raise ValueError("invalid proxy URL")
            p = urlsplit(proxy)
            if p.scheme not in ("http", "https", "socks5", "socks5h") or not p.hostname or p.path not in ("", "/") or p.query or p.fragment:
                raise ValueError("unsupported proxy URL")
            if not p.port:
                raise ValueError("explicit proxy port required")

    @property
    def path(self):
        return "curl-explicit-proxy" if self.proxy else "curl-environment-and-os-routing"

    def get(self, url, family=0, headers_only=False):
        validate_url(url)
        if not self.executable:
            return Response(error="curl_unavailable")
        command = [self.executable, "--disable", "--silent", "--show-error", "--max-time", str(self.timeout),
                   "--connect-timeout", str(self.timeout), "--max-filesize", str(MAX_BODY), "--proto", "=http,https",
                   "--write-out", MARKER + "%{http_code}|%{content_type}"]
        if family in (4, 6):
            command.append("-" + str(family))
        if headers_only:
            command.extend(["--head", "--output", os.devnull])
        proxy_config = None
        if self.proxy:
            # Credentials stay in stdin, not process arguments or reports.
            escaped = self.proxy.replace("\\", "\\\\").replace('"', '\\"')
            proxy_config = 'proxy = "' + escaped + '"\nnoproxy = ""\n'
            command.extend(["--config", "-"])
        command.extend(["--url", url])
        try:
            process = self.runner(command, input=proxy_config, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=self.timeout + 2,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            return Response(error="deadline_exceeded")
        except OSError:
            return Response(error="transport_unavailable")
        if process.returncode:
            return Response(error="curl_exit_" + str(process.returncode))
        if len(process.stdout) > MAX_BODY + 1024 or MARKER not in process.stdout:
            return Response(error="invalid_or_oversized_response")
        body, metadata = process.stdout.rsplit(MARKER, 1)
        code, _, mime = metadata.strip().partition("|")
        try:
            status = int(code)
        except ValueError:
            return Response(error="invalid_status")
        if not 100 <= status <= 599:
            return Response(error="invalid_status")
        return Response(status, body, mime[:120])


def parse_ip_response(response, parser, family):
    from .policy import normalize_ip, public_ip

    if response.error:
        raise ValueError(response.error)
    if response.status != 200:
        raise ValueError("http_" + str(response.status))
    if parser == "trace":
        fields = dict(line.split("=", 1) for line in response.body.splitlines() if "=" in line)
        value = fields.get("ip", "")
    elif parser == "json":
        body = json.loads(response.body)
        if not isinstance(body, dict):
            raise ValueError("invalid_json_shape")
        value = body.get("ip", "")
    else:
        raise ValueError("unknown_parser")
    address = public_ip(value)
    if normalize_ip(address).version != family:
        raise ValueError("address_family_mismatch")
    return address


def application_state(response):
    if response.error:
        return "transport_unverified"
    if response.status == 401:
        return "authentication_required"
    if response.status == 403:
        return "access_denied"
    if response.status == 429:
        return "rate_limited"
    if 200 <= response.status < 300:
        return "http_success_only"
    if 300 <= response.status < 400:
        return "redirect_not_followed"
    if response.status >= 500:
        return "server_error"
    return "http_error"
