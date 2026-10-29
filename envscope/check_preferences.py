"""Persistent optional probes, without weakening required evidence or IP policy."""
from .inspection import ids, resolve, validate_selection


GROUPS = (
    ('ip-consistency', '出口变化比较', ('baseline.ip_stability',)),
    ('dns', 'DNS 配置与权威出口', ('baseline.dns', 'dns.leak')),
    ('webrtc', 'UDP 与浏览器 WebRTC', ('baseline.webrtc', 'udp.stun', 'browser.webrtc')),
    ('client-language', 'Claude 客户端语言', ('baseline.language',)),
    ('asn', 'ASN 归属资料', ('baseline.asn',)),
    ('ecosystem', '外围服务连接', ('extra.ecosystem',)),
)
DEFAULTS = {'disabled': [], 'allow_optional_failures': False, 'logging': True}
# Explicit address-policy failures always remain blockers. This list deliberately
# excludes UDP, ICE, HTTP, TLS, region eligibility, credentials and routing.
SOFTENABLE = frozenset(('baseline.ip_stability', 'baseline.dns', 'baseline.language',
                        'baseline.asn', 'extra.ecosystem'))
OPTIONAL_WARNINGS = frozenset(('baseline.ip_stability', 'extra.ecosystem'))


def validate(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError('检测偏好包含未知字段')
    value = {**DEFAULTS, **value}
    disabled = value['disabled']
    if (not isinstance(disabled, list) or len(disabled) > len(GROUPS)
            or any(not isinstance(v, str) for v in disabled) or len(set(disabled)) != len(disabled)
            or set(disabled) - {g[0] for g in GROUPS}
            or any(type(value[k]) is not bool for k in ('allow_optional_failures', 'logging'))):
        raise ValueError('请选择有效且不重复的可选检查，开关必须为布尔值')
    return {**value, 'disabled': sorted(disabled)}


def protected(settings):
    from .target_environment import plan
    target = plan(settings)
    required = set(target['required']) if target else {
        'target.region', 'http.egress', 'http.ipv6', 'udp.stun', 'browser.webrtc',
        'extra.dns_resolution', 'extra.tls', 'baseline.reachability'}
    # The region guard and its dependencies remain measured in every full run.
    return resolve(sorted((required | {'target.region'}) & ids()))


def selection(settings, requested=None):
    """A deliberate single-run selection overrides disabled optional groups.

    The default button and background worker use the saved groups. Dependencies
    of required target checks cannot be disabled through optional preferences.
    A user may still run a partial check; missing mandatory evidence stays missing.
    """
    requested = validate_selection(requested)
    if requested is not None:
        return requested
    config = validate(settings.get('check_config', {}))
    disabled = {check for key, _, checks in GROUPS if key in config['disabled'] for check in checks}
    disabled -= protected(settings)
    return sorted(ids() - disabled) if disabled else None


def catalog(settings):
    config = validate(settings.get('check_config', {}))
    required = protected(settings)
    return {**config, 'groups': [{'id': key, 'title': title, 'checks': list(checks),
                                  'required': sorted(set(checks) & required)} for key, title, checks in GROUPS],
            'default_checks': selection(settings),
            'note': '必需项目及其依赖始终保留。未检测不算通过；单项检测可临时覆盖保存的跳过偏好。'}


def nonblocking_failures(report, settings):
    config = validate(settings.get('check_config', {}))
    if not config['allow_optional_failures']:
        return set()
    return {f['id'] for f in report.get('findings', [])
            if _optional_problem(f) and f['id'] not in protected(settings)
            and not any(isinstance(e, dict) and e.get('tls_verified') is False for e in f.get('evidence', []))}


def _optional_problem(finding):
    return (finding['id'] in SOFTENABLE and finding['status'] == 'fail'
            or finding['id'] in OPTIONAL_WARNINGS and finding['status'] == 'warn')


def blocking_optional(report, settings):
    return {f['id'] for f in report.get('findings', []) if _optional_problem(f)} - nonblocking_failures(report, settings)
