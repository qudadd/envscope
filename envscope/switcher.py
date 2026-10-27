"""Import already saved claude-switcher checkdetail text without executing it."""
import re

from .model import Finding, Status


def import_text(text):
    findings = []
    for line in text.splitlines()[:256]:
        match = re.fullmatch(r"([^=\r\n]{1,80})=(ok|warn|fail)(?::(.*))?", line.strip())
        if not match:
            continue
        label, reported, detail = match.groups()
        findings.append(Finding("legacy." + str(len(findings) + 1), label,
                                Status.WARN if reported in ("fail", "warn") else Status.UNKNOWN,
                                "已导入上游报告，尚未独立重测", "claude-switcher-import",
                                [{"reported_status": reported, "reported_detail": (detail or "")[:1024]}],
                                ["上游 ok 不转换为 EnvScope 通过；原始报告不证明当前状态。" ]))
    if not findings:
        raise ValueError("no recognized checkdetail rows")
    return findings
