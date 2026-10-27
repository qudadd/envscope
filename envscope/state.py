"""Private application settings and redacted diagnostic history."""
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from .policy import Policy, public_ip
from .report import diff_reports, redact, validate_report

DEFAULTS = {"country": "", "timezone": "", "locale": "", "client": "auto", "proxy_group": "", "webrtc_policy": "proxy",
            "allowed_ipv4": [], "allowed_ipv6": [], "require_guard": True, "require_rules": True, "usage": "auto"}


def validate_settings(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError("unknown settings")
    proposed = {**DEFAULTS, **value}
    for field in ("country", "timezone", "locale", "client", "proxy_group", "webrtc_policy"):
        if not isinstance(proposed[field], str) or len(proposed[field]) > 100 or any(ord(c) < 32 for c in proposed[field]):
            raise ValueError("invalid text setting")
    proposed["country"] = proposed["country"].upper()
    if proposed["country"] and not re.fullmatch("[A-Z]{2}", proposed["country"]):
        raise ValueError("invalid country")
    if proposed["client"] not in ("auto", "clash-verge", "shadowrocket", "sing-box", "clashx", "surge", "other"):
        raise ValueError("invalid client")
    if proposed["webrtc_policy"] not in ("proxy", "reject"):
        raise ValueError("invalid WebRTC policy")
    if proposed["usage"] not in ("auto", "desktop", "cli", "both"):
        raise ValueError("invalid usage")
    for field, version in (("allowed_ipv4", 4), ("allowed_ipv6", 6)):
        if (not isinstance(proposed[field], list) or len(proposed[field]) > 32
                or any(not isinstance(item, str) for item in proposed[field])):
            raise ValueError("invalid allowed networks")
        networks = [ipaddress.ip_network(item, strict=False) for item in proposed[field]]
        if any(n.version != version for n in networks):
            raise ValueError("wrong address family")
        proposed[field] = [str(n) for n in networks]
    if any(type(proposed[f]) is not bool for f in ("require_guard", "require_rules")):
        raise ValueError("invalid boolean setting")
    return proposed


class StateStore:
    def __init__(self, root=None, memory=False):
        self.root = Path(root) if root else Path.home() / ".envscope"
        self.memory = memory
        self._settings = validate_settings({})
        self._history = []
        self._reports = {}
        self._key = secrets.token_bytes(32)
        self._previous_settings = None

    def _read(self, name, fallback):
        if self.memory:
            return fallback
        path = self.root / name
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 2097152:
                return fallback
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return fallback

    def _write(self, name, value):
        if self.memory:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise ValueError("state directory must not be a symlink")
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or not target.parent.resolve().is_relative_to(self.root.resolve()):
            raise ValueError("invalid state path")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, delete=False, prefix=".envscope-") as file:
            json.dump(value, file, ensure_ascii=False, indent=2)
            temporary = Path(file.name)
        try:
            if os.name != "nt":
                temporary.chmod(0o600)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def settings(self):
        try:
            return validate_settings(self._settings if self.memory else self._read("settings.private.json", {}))
        except ValueError:
            return validate_settings({})

    def save_settings(self, value):
        if not isinstance(value, dict):
            raise ValueError("invalid settings")
        proposed = validate_settings({**self.settings(), **value})
        previous = self.settings()
        if proposed == previous:
            return proposed
        self._write("settings.previous.private.json", previous)
        self._write("settings.private.json", proposed)
        self._settings = proposed
        self._previous_settings = previous
        return proposed

    def restore_settings(self):
        previous = self._previous_settings if self.memory else self._read("settings.previous.private.json", None)
        if previous is None:
            raise ValueError("no previous settings")
        return self.save_settings(validate_settings(previous))

    def policy(self):
        p = self.settings()
        return Policy(allowed_ipv4=tuple(ipaddress.ip_network(n) for n in p["allowed_ipv4"]),
                      allowed_ipv6=tuple(ipaddress.ip_network(n) for n in p["allowed_ipv6"]))

    def history(self):
        value = self._history if self.memory else self._read("history.private.json", [])
        return [r for r in value if isinstance(r, dict) and isinstance(r.get("id"), str)
                and re.fullmatch(r"[0-9a-f-]{36}", r["id"])][-50:] if isinstance(value, list) else []

    def _signature(self, findings):
        key = self._read("history-key.private.json", self._key.hex())
        if not isinstance(key, str) or not re.fullmatch("[0-9a-f]{64}", key):
            key = self._key.hex()
        addresses = set()
        for finding in findings:
            if finding["id"] not in ("http.egress", "http.ipv6"):
                continue
            for obs in finding["evidence"]:
                try:
                    addresses.add(public_ip(obs.get("ip")))
                except (ValueError, AttributeError):
                    continue
        signature = hmac.new(bytes.fromhex(key), json.dumps(sorted(addresses)).encode(), hashlib.sha256).hexdigest() if addresses else None
        return signature, key

    def address_change(self, findings):
        signature, key = self._signature(findings)
        key_id = hashlib.sha256(bytes.fromhex(key)).hexdigest()
        previous = next((h.get("address_signature") for h in reversed(self.history())
                         if h.get("address_signature") and h.get("comparison_key") == key_id), None)
        return previous != signature if previous and signature else None

    def record(self, raw_report):
        validate_report(raw_report)
        safe = redact(raw_report)
        signature, key = self._signature(raw_report["findings"])
        record = {"id": raw_report["report_id"], "created_at": raw_report["created_at"],
                  "verdict": raw_report["decision"]["verdict"], "counts": raw_report["decision"]["counts"],
                  "address_signature": signature, "comparison_key": hashlib.sha256(bytes.fromhex(key)).hexdigest()}
        previous = self.history()
        self._write("history-key.private.json", key)
        self._write("history/" + record["id"] + ".private.json", safe)
        self._write("history.private.json", (previous + [record])[-50:])
        self._history = (previous + [record])[-50:]
        self._reports[record["id"]] = safe
        for expired in previous[:-49]:
            self._reports.pop(expired["id"], None)
            if not self.memory:
                path = self.root / "history" / (expired["id"] + ".private.json")
                if path.parent.resolve().is_relative_to(self.root.resolve()) and not path.is_symlink():
                    path.unlink(missing_ok=True)
        return record

    def report(self, report_id):
        if not isinstance(report_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", report_id):
            raise ValueError("invalid history id")
        return self._reports.get(report_id) if self.memory else self._read("history/" + report_id + ".private.json", None)

    def compare(self, before, after):
        old, new = self.report(before), self.report(after)
        if old is None or new is None:
            raise ValueError("history report not found")
        entries = {r["id"]: r for r in self.history()}
        a, b = entries.get(before, {}), entries.get(after, {})
        return {"changes": diff_reports(old, new),
                "observed_address_set_changed": a.get("address_signature") != b.get("address_signature")
                if a.get("address_signature") and b.get("address_signature") and a.get("comparison_key") == b.get("comparison_key") else None,
                "note": "仅比较这两次有效观测的出口集合；地址变化不等同泄漏。"}
