from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path

from .model import Finding, Status


KNOWN_CHECKS = {
    "system.inventory", "network.route", "http.egress", "http.ipv6",
    "udp.stun", "dns.leak", "browser.webrtc", "runtime.config",
}
PRIVACY_CHECKS = ("http.egress", "http.ipv6", "udp.stun", "dns.leak", "browser.webrtc")


def normalize_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("invalid IP address")
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def public_ip(value):
    address = normalize_ip(value)
    if not address.is_global or address.is_multicast:
        raise ValueError("not a globally routable unicast address")
    return str(address)


@dataclass(frozen=True)
class Policy:
    profile: str = "privacy"
    allowed_ipv4: tuple = ()
    allowed_ipv6: tuple = ()
    required_checks: tuple = PRIVACY_CHECKS

    @classmethod
    def load(cls, path=None, profile="privacy"):
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig")) if path else {}
        if not isinstance(raw, dict) or set(raw) - {"allowed_ipv4", "allowed_ipv6", "required_checks"}:
            raise ValueError("policy must contain only allowed_ipv4, allowed_ipv6, required_checks")
        networks = {}
        for name, version in (("allowed_ipv4", 4), ("allowed_ipv6", 6)):
            items = raw.get(name, [])
            if not isinstance(items, list) or len(items) > 128:
                raise ValueError("allowlist must be an array with at most 128 networks")
            converted = []
            for item in items:
                if not isinstance(item, str):
                    raise ValueError("network must be a string")
                network = ipaddress.ip_network(item, strict=False)
                if network.version != version:
                    raise ValueError("allowlist address family mismatch")
                converted.append(network)
            networks[name] = tuple(converted)
        required = raw.get("required_checks", list(PRIVACY_CHECKS if profile == "privacy" else ("http.egress",)))
        if (not isinstance(required, list) or not required or len(required) > len(KNOWN_CHECKS)
                or any(not isinstance(k, str) or k not in KNOWN_CHECKS for k in required)
                or len(required) != len(set(required))):
            raise ValueError("required_checks contains an empty, duplicate, or unknown check")
        return cls(profile, networks["allowed_ipv4"], networks["allowed_ipv6"], tuple(required))

    def networks_for(self, version):
        return self.allowed_ipv4 if version == 4 else self.allowed_ipv6


def decide(findings, required):
    by_id = {f.id: f for f in findings}
    failed = [f.id for f in findings if f.status == Status.FAIL]
    missing = [k for k in required if k not in by_id or by_id[k].status in (Status.UNKNOWN, Status.SKIPPED)]
    warnings = [f.id for f in findings if f.status == Status.WARN]
    verdict = "blocked" if failed else "incomplete" if missing else "review" if warnings else "clear_in_scope"
    return {
        "verdict": verdict,
        "failed": failed,
        "unverified_required": missing,
        "warnings": warnings,
        "counts": {s.value: sum(f.status == s for f in findings) for s in Status},
    }


def assess_addresses(check_id, title, observations, policy, baseline=(), scope="native", minimum=1):
    valid = []
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        try:
            ip = public_ip(obs.get("ip"))
        except (ValueError, TypeError):
            continue
        valid.append((normalize_ip(ip), obs))
    limits = ["只覆盖列出的探测端点、地址族、传输路径和观测时间。"]
    if not valid:
        return Finding(check_id, title, Status.UNKNOWN, "未获得有效公网地址，不能判定无泄漏", scope, observations, limits)
    outside, unconfigured = [], []
    for addr, _ in valid:
        allowed = policy.networks_for(addr.version)
        if allowed and not any(addr in network for network in allowed):
            outside.append(str(addr))
        if not allowed:
            unconfigured.append(addr)
    if outside:
        return Finding(check_id, title, Status.FAIL, "观测地址超出明确配置的允许范围", scope, observations, limits)
    families = {a.version for a, _ in valid}
    enough_sources = all(len({o.get("source", "unknown") for a, o in valid if a.version == family}) >= minimum for family in families)
    if not enough_sources:
        return Finding(check_id, title, Status.WARN, "有效独立观测源不足，结果仅供复核", scope, observations, limits)
    if unconfigured:
        baseline_set = set()
        for value in baseline:
            try:
                baseline_set.add(normalize_ip(value))
            except (ValueError, TypeError):
                pass
        if baseline_set and any(a not in baseline_set for a in unconfigured):
            return Finding(check_id, title, Status.WARN, "存在不同于同一场景 HTTP 观测的地址；不能据此断言是真实 IP", scope, observations, limits)
        families = {a.version for a in unconfigured}
        if check_id == "http.ipv6" or any(not any(b.version == family for b in baseline_set) for family in families):
            return Finding(check_id, title, Status.WARN, "已观测公网地址，尚未配置该地址族的允许范围或可比较基线", scope, observations, limits)
    return Finding(check_id, title, Status.PASS, "本次有效观测符合允许范围或同场景基线", scope, observations, limits)


def assess_http(observations, policy, version=4, scope="native"):
    check_id = "http.egress" if version == 4 else "http.ipv6"
    title = "HTTP IPv4 出口交叉验证" if version == 4 else "HTTP IPv6 出口观测"
    usable, normalized_observations = [], []
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        clean = dict(obs)
        try:
            address = normalize_ip(obs.get("ip"))
            if address.version == version:
                usable.append(obs)
            else:
                clean.pop("ip", None)
                clean["error"] = "address_family_mismatch"
        except (ValueError, TypeError, AttributeError):
            clean.pop("ip", None)
        normalized_observations.append(clean)
    baseline = [o["ip"] for o in usable]
    result = assess_addresses(check_id, title, normalized_observations, policy, baseline, scope, minimum=2)
    if result.status != Status.FAIL and not policy.networks_for(version):
        unique = {str(normalize_ip(o["ip"])) for o in usable}
        if len(unique) > 1:
            result.status = Status.WARN
            result.summary = "独立 HTTP 观测源返回不同出口；可能存在多出口或分流，需要复核"
    return result
