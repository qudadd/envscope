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
        if not isinstance(f.get("suggestion", ""), str) or len(f.get("suggestion", "")) > 1000:
            raise ValueError("invalid suggestion")
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
    from .diagnosis import diagnose
    escape = lambda v: html.escape(str(v), quote=True)
    diagnosis = report.get("diagnosis") or diagnose(report)
    problems = []
    for problem in diagnosis["problems"]:
        steps = "".join("<li>" + escape(step) + "</li>" for step in problem["steps"])
        problems.append("<section><h2>" + escape(problem["title"]) + "</h2><p>" + escape(problem["observed"])
                        + "</p><p>" + escape(problem["cause"]) + "</p><ol>" + steps + "</ol></section>")
    normal = "".join("<p>" + escape(s) + "</p>" for s in diagnosis["normal"])
    rows = "".join("<tr><td>" + escape(c["title"]) + "</td><td>" + escape(c["text"]) + "</td></tr>" for c in diagnosis["checks"])
    style = """body{font:14px/1.8 system-ui,sans-serif;background:#fff;color:#202020;max-width:940px;margin:36px auto;padding:0 28px}
h1{font-size:23px;font-weight:600}h2{font-size:17px;margin:0 0 10px}section{border-top:1px solid #e6e6e6;padding:24px 0}
p{margin:8px 0;color:#646464}li{margin:5px 0}small{color:#646464}table{border-collapse:collapse;width:100%;font-size:12px}
td{border-bottom:1px solid #e6e6e6;padding:12px 12px 12px 0;vertical-align:top}td:first-child{width:25%}
"""
    return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            + '<title>EnvScope — 问题与处理方案</title><style>' + style + '</style><header><h1>EnvScope</h1><h2>'
            + escape(diagnosis["headline"]) + '</h2><p>' + escape(diagnosis["summary"]) + '</p><small>'
            + escape(report["created_at"]) + '</small></header><main>' + "".join(problems) + normal
            + '<section><h2>检测范围</h2><p>' + escape(diagnosis["coverage"])
            + '</p><p>此静态报告不执行修复。请回到桌面程序审核方案、执行和复检。</p></section>'
            + '<section><h2>本次检查记录</h2><table>' + rows + '</table></section></main></html>')

def diff_reports(before, after):
    old = {f["id"]: f for f in before["findings"]}
    new = {f["id"]: f for f in after["findings"]}
    return [{"id": key, "before": old.get(key, {}).get("status", "absent"), "after": new.get(key, {}).get("status", "absent")}
            for key in sorted(old.keys() | new.keys())
            if old.get(key, {}).get("status") != new.get(key, {}).get("status")]
