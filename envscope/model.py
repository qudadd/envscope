from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
import uuid

from . import __version__


class Status(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    id: str
    title: str
    status: Status
    summary: str
    scope: str
    evidence: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    suggestion: str = ""

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", self.id):
            raise ValueError("invalid finding id")
        self.status = Status(self.status)

    def to_dict(self):
        value = asdict(self)
        value["status"] = self.status.value
        return value


def make_report(findings, policy, mode="audit", preferences=None):
    from .policy import decide

    ids = [f.id for f in findings]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate finding ids")
    decision = decide(findings, policy.required_checks)
    report = {
        "schema_version": 1,
        "tool": "envscope",
        "version": __version__,
        "report_id": str(uuid.uuid4()),
        "created_at": utc_now(),
        "mode": mode,
        "policy": {
            "profile": policy.profile,
            "required_checks": list(policy.required_checks),
            "explicit_ipv4_allowlist": bool(policy.allowed_ipv4),
            "explicit_ipv6_allowlist": bool(policy.allowed_ipv6),
        },
        "decision": decision,
        "findings": [f.to_dict() for f in findings],
        "boundary": "只读诊断；结论仅覆盖本次观测与配置范围，不证明零泄漏或防火墙保护。",
    }
    from .diagnosis import diagnose
    report["diagnosis"] = diagnose(report, preferences)
    return report
