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


def make_report(findings, policy, mode="audit", preferences=None, selected_checks=None):
    from .policy import decide
    from .target_environment import build_findings, plan, summary, scoped_preferences, FIELDS

    preferences = preferences or {}
    from .check_preferences import selection
    selected_checks = selection(preferences, selected_checks)
    from .regions import region_finding
    from .inspection import scope_findings, selection_info, repair_options
    findings = list(findings)
    findings = scope_findings(findings, selected_checks)
    findings = findings + [region_finding(findings, preferences)] + build_findings(findings, preferences)
    findings = scope_findings(findings, selected_checks)

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
        "usage": (preferences or {}).get("usage", "auto"),
        "policy": {
            "profile": policy.profile,
            "required_checks": list(policy.required_checks),
            "explicit_ipv4_allowlist": bool(policy.allowed_ipv4),
            "explicit_ipv6_allowlist": bool(policy.allowed_ipv6),
        },
        "decision": decision,
        "findings": [f.to_dict() for f in findings],
        "selection": selection_info(selected_checks),
        "boundary": "只读诊断；结论仅覆盖本次观测与配置范围，不证明零泄漏或防火墙保护。",
    }
    target_plan = plan(preferences)
    from .check_preferences import validate, nonblocking_failures
    config = validate(preferences.get('check_config', {}))
    report['check_config'] = {**config, 'nonblocking_failures': sorted(nonblocking_failures(report, preferences))}
    if target_plan:
        report['environment'] = {**summary(preferences), **target_plan,
                                 'targets': {k: preferences.get(k) for k in sorted(FIELDS)}}
    from .assessment import assessment
    report["assessment"] = assessment(report, preferences)
    from .diagnosis import diagnose
    report["diagnosis"] = diagnose(report, scoped_preferences(preferences))
    report['repair_options'] = repair_options(report)
    from .claude_checks import checklist
    report["claude_checks"] = checklist(report, preferences)
    from .guide import usage_guide
    report["guide"] = usage_guide(report)
    from .readiness import launch_readiness
    report["launch"] = launch_readiness(report, preferences)
    from .coverage import environment_portrait
    report['portrait'] = environment_portrait(report)
    return report
