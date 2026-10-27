import copy
import html
import ipaddress
import json
from pathlib import Path
import re

from .transport import display_url

VERDICTS = {"blocked": "发现策略违反", "incomplete": "检测尚不完整", "review": "需要复核", "clear_in_scope": "配置范围内通过"}
STATUSES = {"pass": "范围内通过", "warn": "需要复核", "fail": "策略违反", "unknown": "未知", "skipped": "未检测"}


def redact(report):
    """Per-report aliases preserve equality without publishing reversible IP hashes."""
    aliases = {}

    def replace_address(match):
        value = match.group(0)
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        canonical = str(addr)
        if canonical not in aliases:
            aliases[canonical] = "[ipv" + str(addr.version) + "-" + str(len(aliases) + 1) + "]"
        return aliases[canonical]

    def clean(value, key=""):
        if isinstance(value, dict):
            return {k: clean(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v, key) for v in value]
        if not isinstance(value, str):
            return value
        if any(token in key.lower() for token in ("password", "secret", "credential", "authorization", "token", "macaddress", "physicaladdress")):
            return "[redacted]"
        if key.lower() in ("name", "interfacedescription", "ifname"):
            return "[interface]"
        value = re.sub(r"(?i)([A-Z]:[\\/]Users[\\/])[^\\/\r\n]+", r"\1[user]", value)
        value = re.sub(r"(/Users/|/home/)[^/\r\n]+", r"\1[user]", value)
        value = re.sub(r"https?://[^\s<>\"']+", lambda m: display_url(m.group(0)), value)
        value = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", replace_address, value)
        value = re.sub(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?:%[\w.-]+)?(?![\w:])", replace_address, value)
        return value

    result = clean(copy.deepcopy(report))
    result["contains_sensitive"] = False
    result["redaction_note"] = "地址使用本报告内别名；跨报告不能用别名判断 IP 是否相同。时区、语言和软件信息仍可能识别环境，请自行复核后分享。"
    return result


def validate_report(value):
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("tool") != "envscope":
        raise ValueError("unsupported report")
    findings = value.get("findings")
    if (not isinstance(value.get("created_at"), str) or not isinstance(value.get("policy"), dict)
            or not isinstance(value["policy"].get("profile"), str)):
        raise ValueError("invalid report header")
    if not isinstance(findings, list) or len(findings) > 256:
        raise ValueError("invalid report findings")
    ids = set()
    for f in findings:
        if (not isinstance(f, dict) or not isinstance(f.get("id"), str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", f["id"]) or f["id"] in ids
                or f.get("status") not in STATUSES or any(not isinstance(f.get(k), str) for k in ("title", "summary", "scope"))
                or not isinstance(f.get("evidence"), list) or not isinstance(f.get("limitations"), list)):
            raise ValueError("invalid or duplicate finding")
        ids.add(f["id"])
    if not isinstance(value.get("decision"), dict) or value["decision"].get("verdict") not in VERDICTS:
        raise ValueError("invalid decision")
    return value


def read_report(path):
    file = Path(path)
    if file.stat().st_size > 2097152:
        raise ValueError("report too large")
    return validate_report(json.loads(file.read_text(encoding="utf-8-sig")))


def write_json(report, path):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def html_report(report):
    escape = lambda v: html.escape(str(v), quote=True)
    rows = []
    for f in report["findings"]:
        details = json.dumps(f["evidence"], ensure_ascii=False, indent=2)
        limits = "".join("<li>" + escape(v) + "</li>" for v in f["limitations"])
        rows.append('<section><div class="row"><h2>' + escape(f["title"]) + '</h2><span class="status ' + escape(f["status"]) + '">'
                     + escape(STATUSES[f["status"]]) + '</span></div><p>' + escape(f["summary"]) + '</p><small>'
                     + escape(f["id"] + " · " + f["scope"]) + '</small><details><summary>查看证据与边界</summary><pre>'
                     + escape(details) + '</pre><ul>' + limits + '</ul></details></section>')
    style = '''body{font:13px/1.8 system-ui,sans-serif;background:#fff;color:#171717;max-width:850px;margin:36px auto;padding:0 24px}
header{margin-bottom:25px}h1{font-size:23px;font-weight:500;margin:0 0 18px}h2{font-size:13px;font-weight:500;margin:0}
.verdict{font-size:16px}.row{display:flex;align-items:baseline;gap:20px;justify-content:space-between}
section{border-top:1px solid #e4e4e4;padding:18px 0}p{margin:7px 0;color:#666}small{font-size:10px;color:#777}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.8 ui-monospace,monospace;padding:12px 0}
.status{font-size:11px;color:#666;white-space:nowrap}.fail{color:#171717;font-weight:650;text-decoration:underline}
summary{cursor:pointer;margin-top:10px;font-size:11px;color:#777}li{overflow-wrap:anywhere;font-size:11px;color:#777}
'''
    return '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>EnvScope — 诊断报告</title><style>''' + style + '</style><header><h1>EnvScope</h1><p class="verdict">' + escape(VERDICTS[report["decision"]["verdict"]]) + '</p><p>' + escape(report.get("boundary", "")) + '</p><small>' + escape(report["created_at"]) + " / " + escape(report["policy"]["profile"]) + '</small></header><main>' + "".join(rows) + '</main></html>'


def diff_reports(before, after):
    old = {f["id"]: f for f in before["findings"]}
    new = {f["id"]: f for f in after["findings"]}
    return [{"id": key, "before": old.get(key, {}).get("status", "absent"), "after": new.get(key, {}).get("status", "absent")}
            for key in sorted(old.keys() | new.keys())
            if old.get(key, {}).get("status") != new.get(key, {}).get("status")]
