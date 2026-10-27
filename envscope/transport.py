"""Bounded curl transport; explicit proxies never retry over another path."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
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
    timings: dict = field(default_factory=dict)
    tls_verified: object = None
    clock_offset_seconds: object = None
    http_version: str = ""


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
                   "--globoff", "--write-out", MARKER + "%{http_code}|%{content_type}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{ssl_verify_result}|%{http_version}"]
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
        headers = ""
        try:
            with tempfile.TemporaryDirectory(prefix="envscope-http-") as directory:
                file = Path(directory) / "headers.private"
                command.extend(["--dump-header", str(file)])
                started = datetime.now(timezone.utc)
                process = self.runner(command, input=proxy_config, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=self.timeout + 2,
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                finished = datetime.now(timezone.utc)
                if file.is_file() and file.stat().st_size <= MAX_BODY:
                    headers = file.read_text(encoding="iso-8859-1", errors="replace")
        except subprocess.TimeoutExpired:
            return Response(error="deadline_exceeded")
        except OSError:
            return Response(error="transport_unavailable")
        if process.returncode:
            return Response(error="curl_exit_" + str(process.returncode), tls_verified=False if process.returncode in (51, 60, 83) else None)
        if len(process.stdout) > MAX_BODY + 1024 or MARKER not in process.stdout:
            return Response(error="invalid_or_oversized_response")
        body, metadata = process.stdout.rsplit(MARKER, 1)
        fields = metadata.strip().split("|")
        code, mime = fields[0], fields[1] if len(fields) > 1 else ""
        try:
            status = int(code)
        except ValueError:
            return Response(error="invalid_status")
        if not 100 <= status <= 599:
            return Response(error="invalid_status")
        timings, verified = {}, None
        if len(fields) == 9:
            try:
                values = [float(v) for v in fields[2:7]]
                if not all(math.isfinite(v) and 0 <= v <= self.timeout + 3 for v in values):
                    raise ValueError("invalid timings")
                lookup, connect, tls, first, total = values
                if not lookup <= connect <= first <= total or tls and not connect <= tls <= first:
                    raise ValueError("inconsistent timings")
                timings = {"dns_ms": round(lookup * 1000, 1), "tcp_ms": round(max(0, connect - lookup) * 1000, 1),
                           "tls_ms": round(max(0, tls - connect) * 1000, 1) if tls else None,
                           "first_byte_ms": round(first * 1000, 1), "total_ms": round(total * 1000, 1)}
                if urlsplit(url).scheme == "https" and tls > 0:
                    verified = int(fields[7]) == 0
            except ValueError:
                pass
        offset = None
        # Retain no raw headers/cookies. Account for cache Age before comparing.
        blocks = headers.replace("\r\n", "\n").split("\n\n")
        block = next((b for b in reversed(blocks) if b.startswith("HTTP/")), "")
        selected = {k.lower().strip(): v.strip() for line in block.splitlines()[1:] if ":" in line for k, v in [line.split(":", 1)] if k.lower().strip() in ("date", "age")}
        try:
            date = parsedate_to_datetime(selected["date"])
            age = int(selected.get("age", "0"))
            if date.tzinfo is not None and 0 <= age <= 86400 and verified is True:
                midpoint = started + (finished - started) / 2
                offset = round(date.timestamp() + age - midpoint.timestamp(), 1)
        except (KeyError, ValueError, TypeError, OverflowError):
            pass
        return Response(status, body, mime[:120], timings=timings, tls_verified=verified,
                        clock_offset_seconds=offset, http_version=fields[8][:12] if len(fields) == 9 else "")


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
    if response.status == 407:
        return "proxy_authentication_required"
    if response.status == 429:
        return "rate_limited"
    if 200 <= response.status < 300:
        return "http_success_only"
    if 300 <= response.status < 400:
        return "redirect_not_followed"
    if response.status >= 500:
        return "server_error"
    return "http_error"


def response_evidence(url, response):
    return {"endpoint": display_url(url), "http_status": response.status, "access": application_state(response),
            "error": response.error, "timings": response.timings, "tls_verified": response.tls_verified,
            "clock_offset_seconds": response.clock_offset_seconds, "http_version": response.http_version}
