from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from envscope.controller import inspect_controller, validate_controller
from envscope.model import Finding, Status, make_report
from envscope.policy import Policy
from envscope.report import diff_reports, html_report, redact, validate_report
from envscope.transport import MARKER, CurlTransport, Response, application_state, parse_ip_response


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(403 if self.path == "/denied" else 200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"mode":"rule","tun":{"enable":true},"secret":"DO_NOT_EXPORT","ip":"8.8.8.8"}')

    def log_message(self, *args):
        pass


class TransportTests(unittest.TestCase):
    def test_html_challenge_with_http200_is_not_valid_ip(self):
        with self.assertRaises(ValueError):
            parse_ip_response(Response(200, "<html>Challenge</html>"), "json", 4)

    def test_private_and_wrong_family_payload_rejected(self):
        for ip in ("127.0.0.1", "2001:4860::1"):
            with self.assertRaises(ValueError):
                parse_ip_response(Response(200, json.dumps({"ip": ip})), "json", 4)

    def test_target_states_do_not_call_403_or_429_success(self):
        self.assertEqual(application_state(Response(403)), "access_denied")
        self.assertEqual(application_state(Response(429)), "rate_limited")
        self.assertEqual(application_state(Response(401)), "authentication_required")
        self.assertEqual(application_state(Response(500)), "server_error")

    def test_explicit_proxy_is_not_retried_and_credentials_stay_off_argv(self):
        calls = []
        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 7, stdout="", stderr="sensitive diagnostic")
        transport = CurlTransport("http://person:secret@127.0.0.1:8080", runner=runner)
        transport.executable = "test-curl"
        result = transport.get("https://example.org/")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("secret", " ".join(calls[0][0]))
        self.assertIn('noproxy = ""', calls[0][1]["input"])
        self.assertEqual(result.error, "curl_exit_7")
        self.assertNotIn("sensitive", str(result))

    def test_local_http_roundtrip_and_controller_secret_exclusion(self):
        transport = CurlTransport("http://127.0.0.1:1")
        if not transport.executable:
            self.skipTest("curl is unavailable")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = "http://127.0.0.1:" + str(server.server_port)
        try:
            # Explicitly disable ambient proxies for a fixture-only loopback request.
            import os
            with patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}):
                response = CurlTransport().get(origin + "/denied")
            self.assertEqual(response.status, 403)
            finding = inspect_controller(origin, "example-secret")
            self.assertEqual(finding.status, Status.PASS)
            self.assertNotIn("DO_NOT_EXPORT", json.dumps(finding.to_dict()))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_controller_rejects_remote_or_named_host(self):
        for url in ("http://example.org:9090", "http://localhost:9090", "https://127.0.0.1:9090", "http://127.0.0.1:9090/configs"):
            with self.assertRaises(ValueError):
                validate_controller(url)


class ReportTests(unittest.TestCase):
    def report(self):
        return make_report([Finding("http.egress", "<script>alert(1)</script>", Status.UNKNOWN,
                                    "no observation", "native", [{"ip": "8.8.8.8", "v6": "2001:4860::1", "local": "192.168.1.2",
                                                                 "url": "https://name:secret@example.org/path?token=private", "secret": "do-not-show"}])], Policy())

    def test_default_report_hides_addresses_credentials_and_query(self):
        safe = redact(self.report())
        text = json.dumps(safe)
        for private in ("8.8.8.8", "2001:4860::1", "192.168.1.2", "name:secret", "token=private", "do-not-show"):
            self.assertNotIn(private, text)
        self.assertFalse(safe["contains_sensitive"])

    def test_html_is_escaped_and_has_no_external_resources(self):
        page = html_report(redact(self.report()))
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)

    def test_report_rejects_duplicate_checks_and_incomplete_header(self):
        report = self.report()
        report["findings"].append(report["findings"][0])
        with self.assertRaises(ValueError):
            validate_report(report)
        report = self.report()
        del report["policy"]
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_diff_compares_status_not_unstable_redaction_aliases(self):
        before = self.report()
        after = self.report()
        after["findings"][0]["evidence"] = [{"ip": "1.1.1.1"}]
        self.assertEqual(diff_reports(before, after), [])
        after["findings"][0]["status"] = "fail"
        self.assertEqual(diff_reports(before, after)[0]["after"], "fail")
