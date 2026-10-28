"""Origin-bound loopback API with fixed diagnostics and explicit desktop actions."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
import time
import subprocess

from .browser import validate_snapshot
from .model import make_report, Status
from .policy import assess_http
from .probes import audit
from .report import redact
from .state import StateStore
from .operations import Operations, launch_gate
from .accounts import AccountError, PreflightError
from .transport import CurlTransport, desktop_transport
from .diagnosis import compare_diagnoses
from . import __version__


class DesktopHandler(SimpleHTTPRequestHandler):
    # Windows MIME registrations can override Python's module defaults.
    # ES modules must have a JavaScript type when nosniff is enabled.
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map,
                      ".mjs": "text/javascript", ".js": "text/javascript",
                      ".css": "text/css", ".html": "text/html"}

    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def json_response(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        try:
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionError, TimeoutError):
            # Closing/reloading a page cancels pending catalog responses. That
            # is not an operation failure and must not send a second response.
            self.close_connection = True

    def expected_origin(self):
        return "http://127.0.0.1:" + str(self.server.server_port)

    def valid_host(self):
        return self.headers.get("Host") == "127.0.0.1:" + str(self.server.server_port)

    def do_GET(self):
        if not self.valid_host() or self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.json_response(403, {"error": "invalid_origin"})
            return
        self.server.last_activity = time.monotonic()
        if self.path == "/api/session":
            self.json_response(200, {"token": self.server.session_token, "mode": "desktop", "version": __version__,
                                     "shell": "native" if getattr(self.server.operations, "desktop_runtime", None) else "browser"})
        elif (self.path == "/api/catalog" and self.headers.get("X-EnvScope-Token", "").isascii()
              and secrets.compare_digest(self.headers.get("X-EnvScope-Token", ""), self.server.session_token)):
            try:
                value = self.server.operations.catalog()
                value["history"] = [{k: v for k, v in row.items() if k != "address_signature"} for row in value["history"]]
                self.json_response(200, value)
            except (ValueError, OSError, AccountError):
                self.json_response(500, {"error": "catalog_unavailable"})
        elif self.path.startswith("/api/"):
            self.json_response(404, {"error": "unknown_endpoint"})
        else:
            super().do_GET()

    def do_OPTIONS(self):
        self.json_response(405, {"error": "cross_origin_not_supported"})

    def do_POST(self):
        token = self.headers.get("X-EnvScope-Token", "")
        if (not self.valid_host() or self.headers.get("Origin") != self.expected_origin() or not token.isascii()
                or not secrets.compare_digest(token, self.server.session_token)):
            self.json_response(403, {"error": "invalid_session"})
            return
        self.server.last_activity = time.monotonic()
        if self.path == "/api/quit":
            if not self.server.audit_lock.acquire(blocking=False):
                self.json_response(409, {"error": "audit_running"})
                return
            self.json_response(200, {"stopped": True})
            self.server.audit_lock.release()
            if getattr(self.server, "quit_callback", None):
                self.server.quit_callback()
            else:
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.path not in ("/api/audit", "/api/action"):
            self.json_response(404, {"error": "unknown_endpoint"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self.json_response(415, {"error": "json_required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 65536:
                self.json_response(413, {"error": "invalid_body_size"})
                return
            self.connection.settimeout(5)
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("truncated body")
            request = json.loads(body)
            if not isinstance(request, dict):
                raise ValueError("JSON object required")
            if self.path == "/api/audit":
                if set(request) != {"snapshot"}:
                    raise ValueError("only browser observations are accepted")
                snapshot = validate_snapshot(request["snapshot"])
            elif (set(request) != {"action", "params", "confirmed"} or not isinstance(request["action"], str)
                    or len(request["action"]) > 40 or not isinstance(request["params"], dict) or type(request["confirmed"]) is not bool):
                raise ValueError("invalid fixed action")
        except (ValueError, OSError):
            self.json_response(400, {"error": "invalid_observations"})
            return
        # Bringing an existing window forward must also work during a repair.
        if self.path == "/api/action" and request["action"] == "desktop-show" and not request["params"]:
            self.json_response(200, self.server.operations.run("desktop-show", {}, confirmed=False))
            return
        if not self.server.audit_lock.acquire(blocking=False):
            self.json_response(409, {"error": "audit_running"})
            return
        try:
            if self.path == "/api/audit":
                self.json_response(200, collect_report(self.server, snapshot))
            else:
                def preflight():
                    if not self.server.last_browser:
                        return False
                    try:
                        fresh_browser = validate_snapshot(self.server.last_browser)
                    except ValueError:
                        return False
                    collect_report(self.server, fresh_browser)
                    return launch_gate(self.server.last_raw_report, self.server.store.settings())[0]
                result = self.server.operations.run(request["action"], request["params"], confirmed=request["confirmed"],
                                                    report=self.server.last_raw_report, preflight=preflight)
                if request["action"] == "solution-apply" and result.get("before"):
                    self.server.solution_before = result.pop("before")
                elif request["action"] in ("solution-open", "solution-undo") and result.get("state") in ("opened", "completed") and self.server.last_raw_report:
                    self.server.solution_before = {"problems": [{"id": p["id"], "title": p["title"]} for p in self.server.last_raw_report["diagnosis"]["problems"]]}
                if request["action"] in ("settings-save", "settings-restore", "fix", "install", "update-apply", "set-region", "set-client") or request["action"] in ("solution-apply", "solution-undo") and result.get("state") not in ("confirmation_required", "retest_required"):
                    self.server.last_raw_report = None
                if request["action"] in ("account-switch", "app-launch", "app-restart", "open-safe") and self.server.last_raw_report:
                    result["latest_report"] = redact(self.server.last_raw_report)
                self.json_response(200, result)
        except PreflightError:
            value = {"state": "blocked", "reason": "操作前复检未通过，未提交启动请求，账号文件没有交换。"}
            if self.server.last_raw_report:
                value["latest_report"] = redact(self.server.last_raw_report)
                value["reasons"] = launch_gate(self.server.last_raw_report, self.server.store.settings())[1]
            self.json_response(200, value)
        except (ValueError, AccountError) as error:
            self.json_response(400, {"error": str(error)[:240]})
        except (OSError, subprocess.TimeoutExpired):
            self.json_response(500, {"error": "operation_unavailable_or_deadline"})
        finally:
            self.server.audit_lock.release()
            self.server.last_activity = time.monotonic()


def collect_report(server, snapshot):
    policy = server.store.policy()
    findings = server.auditor(policy, desktop_transport(), online=True, stun=True, ipv6=True, browser=snapshot,
                              baseline_config=server.store.settings())
    changed = server.store.address_change([f.to_dict() for f in findings])
    for finding in findings:
        if finding.id == "browser.webrtc":
            finding.scope = "browser-loopback-session"
        if finding.id == "baseline.ip_stability" and changed is not None:
            finding.status = Status.WARN if changed else Status.PASS
            finding.summary = "出口集合与上次有效观测不同" if changed else "出口集合与上次有效观测相同"
            finding.scope = "two-observation-comparison"
    for family in (4, 6):
        observations = [o for o in snapshot["http"] if o.get("family") == family]
        finding = assess_http(observations, policy, family, "browser-loopback-session")
        finding.id = "browser.http_v" + str(family)
        finding.title = "浏览器 HTTP IPv" + str(family)
        findings.append(finding)
    raw = make_report(findings, policy, "one-click-desktop", server.store.settings())
    if getattr(server, "solution_before", None) is not None:
        raw["resolution"] = compare_diagnoses(server.solution_before, raw["diagnosis"])
        raw["resolution"]["configuration"] = server.operations.config_remedies.verify_receipts(server.solution_before.get("configuration", []))
        raw["resolution"]["configuration_pending"] = server.solution_before.get("configuration_pending", [])
        selected = server.solution_before.get("check")
        if selected:
            current = next((item for item in raw["claude_checks"]["items"] if item["id"] == selected["id"]), None)
            state = "verified" if current and current["status"] == "pass" else "unverified" if not current or current["status"] in ("unknown", "skipped", "not_configured") else "review"
            raw["resolution"]["item"] = {"id": selected["id"], "title": selected["title"], "state": state,
                                           "before": selected["status"], "after": current["status"] if current else "unknown"}
        server.solution_before = None
    server.last_raw_report, server.last_browser = raw, snapshot
    report = redact(raw)
    try:
        server.store.record(raw)
        report["history_saved"] = True
    except (ValueError, OSError):
        report["history_saved"] = False
        report["history_note"] = "本次结果仍可导出；本机历史写入失败。"
    return report


def make_server(port=0, auditor=None, store=None, operations=None):
    web = Path(__file__).parent / "web"
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(DesktopHandler, directory=str(web)))
    server.session_token = secrets.token_urlsafe(32)
    server.audit_lock = threading.Lock()
    server.last_activity = time.monotonic()
    server.auditor = auditor or audit
    server.store = store or StateStore(memory=auditor is not None)
    server.operations = operations or Operations(server.store)
    server.last_raw_report = server.last_browser = None
    return server


def expire_idle(server, seconds=900):
    while not getattr(server, "desktop_stopped", False):
        time.sleep(15)
        if time.monotonic() - server.last_activity > seconds and not server.audit_lock.locked():
            server.shutdown()
            return
