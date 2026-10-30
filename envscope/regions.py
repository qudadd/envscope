"""Versioned official region lists; declarations and IP observations stay distinct.

Checked 2026-10-30 against the current Help Center and API documentation. The
legal page dated 2026-11-12 is not yet effective and is deliberately not used.
Country names are normalized to ISO 3166-1 alpha-2; the Help Center's duplicate
Herzegovina entry is BA and its Mariana Islands entry is MP.
"""
import re
from .model import Finding, Status

CHECKED_AT = '2026-10-30'
CLAUDE_SOURCE = 'https://support.claude.com/en/articles/8461763-where-can-i-access-claude'
API_SOURCE = 'https://platform.claude.com/docs/en/api/supported-regions'
API_REGIONS = frozenset('''AL DZ AD AO AG AR AM AU AT AZ BS BH BD BB BE BZ BJ BT BO BA BW BR BN BG BF BI
CV KH CM CA TD CL CO KM CG CR CI HR CY CZ DK DJ DM DO EC EG SV GQ EE SZ FJ FI FR GA GM GE DE GH GR GD
GT GN GW GY HT VA HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI KW KG LA LV LB LS LR LI LT LU MG MW MY
MV MT MH MR MU MX FM MD MC MN ME MA MZ NA NR NP NL NZ NE NG MK NO OM PK PW PS PA PG PY PE PH PL PT
QA RO RW KN LC VC WS SM ST SA SN RS SC SL SG SK SI SB ZA KR ES LK SR SE CH TW TJ TZ TH TL TG TO TT
TN TR TM TV UG UA AE GB US UY UZ VU VN ZM ZW'''.split())
CLAUDE_REGIONS = API_REGIONS | {'MP'}
NAMES = {'CN':'中国大陆', 'RU':'俄罗斯', 'HK':'中国香港', 'MO':'中国澳门', 'TW':'中国台湾',
         'US':'美国', 'JP':'日本', 'SG':'新加坡', 'GB':'英国', 'UA':'乌克兰'}
PARTIAL = {'UA'}  # API excludes Crimea, Donetsk and Luhansk; country alone cannot decide.


def code(value):
    return value.upper() if isinstance(value, str) and re.fullmatch('[A-Za-z]{2}', value) else None


def name(value):
    return NAMES.get(value, value) + '（' + value + '）' if value in NAMES else value


def region_finding(findings, settings):
    """A supported exit never certifies the user's location or account eligibility."""
    usage = settings.get('usage', 'auto')
    allowed = CLAUDE_REGIONS if usage in ('desktop', 'web') else API_REGIONS
    declared = code(settings.get('usage_country'))
    expected = code(settings.get('country'))
    observations = []
    for finding in findings:
        if finding.id not in ('baseline.country', 'http.egress', 'http.ipv6', 'browser.http_v4', 'browser.http_v6'):
            continue
        for item in finding.evidence:
            if not isinstance(item, dict) or item.get('error'):
                continue
            country = code(item.get('actual') if finding.id == 'baseline.country' else item.get('country'))
            if country:
                observations.append({'check':finding.id, 'country':country})
    observed = {item['country'] for item in observations}
    unsupported = []
    for label, countries in (('申报的实际使用地区', {declared} if declared else set()),
                             ('出口观测', observed), ('设置的出口目标', {expected} if expected else set())):
        missing = sorted(countries - allowed)
        if missing:
            unsupported.append(label + '：' + '、'.join(name(c) for c in missing))
    sources = [CLAUDE_SOURCE] if usage in ('desktop', 'web') else [API_SOURCE] if usage == 'cli' else [CLAUDE_SOURCE, API_SOURCE]
    details = {'declared_country':declared, 'observed_countries':sorted(observed), 'expected_exit_country':expected,
               'observations':observations, 'checked_at':CHECKED_AT, 'sources':sources,
               'unsupported':unsupported, 'physical_location_verified':False, 'account_eligibility_verified':False}
    if unsupported:
        status, summary = Status.FAIL, '官方不支持，地区条件不合格。' + '；'.join(unsupported)
        suggestion = '在该地区不要使用 Claude。先核对填报与 IP 定位是否有误；如有争议请联系 Claude 官方支持。地区限制不能通过更改时区、语言、代理或切换账号修复。'
    elif not declared:
        status, summary = Status.UNKNOWN, '尚未确认实际使用地区；支持地区的出口不能代替所在地说明'
        suggestion = '在“调整目标”中填写实际使用地区，不要填写代理节点所在地。'
    elif declared in PARTIAL or observed & PARTIAL or expected in PARTIAL:
        status, summary = Status.WARN, '地区存在官方子区域限制，需要核对具体所在地'
        suggestion = 'API 名单排除 Crimea、Donetsk、Luhansk；国家代码不足以确认资格，请核对官方页面或联系支持。'
    elif usage in ('cli', 'both') and settings.get('provider', 'anthropic') != 'anthropic':
        status, summary = Status.UNKNOWN, '所列地区未发现名单冲突；云提供方或自定义接口的地区要求仍需核实'
        suggestion = '分别核对 Claude 与实际提供方的官方地区要求；其他提供方的访问不能由官方 API 探测证明。'
    elif not observed:
        status, summary = Status.UNKNOWN, '已记录实际使用地区，但没有取得有效出口国家资料'
        suggestion = '重新检测出口资料；读取失败或超时不能判为地区合格，也不意味着需要管理员权限。'
    else:
        status, summary = Status.PASS, '申报地区与已观测出口均在所选用途的官方支持名单内'
        suggestion = '实际所在地或连接改变后复检；账号、组织及付费资格仍以官方审核为准。'
    return Finding('target.region', 'Claude 官方地区支持', status, summary, 'official-region-list-snapshot', [details],
                   ['依据 '+CHECKED_AT+' 核对的官方名单；IP 定位可能不准确，申报位置未被独立验证。',
                    '中国大陆（CN）与俄罗斯（RU）均不在支持名单中；系统时区和中文界面不作为所在地证据。'], suggestion)
