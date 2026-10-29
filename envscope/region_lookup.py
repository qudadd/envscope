"""Read-only IP suggestions, scoped to the form's route and never saved as proof."""
from concurrent.futures import ThreadPoolExecutor
import json
import re

from .model import utc_now
from .policy import public_ip
from .transport import desktop_transport

SOURCES = (('Cloudflare', 'https://www.cloudflare.com/cdn-cgi/trace'),
           ('IPinfo', 'https://ipinfo.io/json'))


def lookup_region(params, transport_factory=desktop_transport):
    if set(params) != {'connection_mode', 'target_proxy'} or params['connection_mode'] not in ('direct', 'tun', 'http_proxy'):
        raise ValueError('请选择连接方式后读取 IP')
    proxy = params['target_proxy']
    from .remedies import safe_local_proxy
    if not isinstance(proxy, str) or proxy and (params['connection_mode'] != 'http_proxy' or
            not proxy.startswith(('http://', 'https://')) or not safe_local_proxy(proxy)):
        raise ValueError('请填写不含凭据的本机 HTTP / HTTPS 代理地址')
    # Temporary routing preferences only. No settings or confirmation are persisted.
    transport = transport_factory({**params, 'environment_confirmed': True})

    def read(source):
        name, url = source
        observation = {'source': name}
        try:
            response = transport.get(url, 4)
            if response.status != 200 or response.error or response.tls_verified is not True:
                return {**observation, 'error': '未取得经过 TLS 校验的成功响应'}
            if name == 'Cloudflare':
                value = dict(line.split('=', 1) for line in response.body.splitlines() if '=' in line)
                value['country'] = value.get('loc')
            else:
                value = json.loads(response.body)
            if not isinstance(value, dict):
                raise ValueError('invalid shape')
            ip = public_ip(value.get('ip'))
            if ':' in ip:
                raise ValueError('unexpected IPv6 response')
            country = value.get('country')
            if not isinstance(country, str) or not re.fullmatch('[A-Z]{2}', country) or country in ('XX', 'ZZ'):
                raise ValueError('invalid country')
            observation.update(ip=ip, country=country)
            timezone = value.get('timezone', '')
            if isinstance(timezone, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_+/-]{0,99}', timezone):
                observation['timezone'] = timezone
            city = value.get('city', '')
            if isinstance(city, str) and len(city) <= 100 and all(ord(c) >= 32 for c in city):
                observation['city'] = city
            return observation
        except (ValueError, TypeError, OSError):
            return {**observation, 'error': '未取得有效的公网 IPv4 与国家数据'}

    with ThreadPoolExecutor(max_workers=2) as pool:
        observations = list(pool.map(read, SOURCES))
    valid = [row for row in observations if row.get('country')]
    result = {'observed_at': utc_now(), 'route': transport.path, 'observations': observations,
              'country': '', 'ip': '', 'timezone': '', 'city': '',
              'scope': '当前所选 HTTP IPv4 路由；不是实际所在地或 Claude 进程出口证明'}
    if not valid:
        return {**result, 'state': 'unavailable', 'reason': '未能读取出口 IP，可重试或手动选择目标国家与城市。'}
    if len({row['country'] for row in valid}) > 1:
        return {**result, 'state': 'conflict', 'reason': 'IP 查询来源返回不同国家，未自动填写目标。请核对代理分流后重新读取。'}
    result['country'] = valid[0]['country']
    if len({row['ip'] for row in valid}) > 1:
        return {**result, 'state': 'partial', 'reason': '各来源国家一致，但 IP 不同。已筛选国家，请手动选择城市；未自动匹配时区。'}
    result['ip'] = valid[0]['ip']
    if len(valid) != len(SOURCES):
        return {**result, 'state': 'partial', 'reason': '只有一个来源返回有效结果。已按该国家筛选城市，请手动确认。'}
    metadata = next(row for row in valid if row['source'] == 'IPinfo')
    result.update(timezone=metadata.get('timezone', ''), city=metadata.get('city', ''))
    return {**result, 'state': 'observed', 'reason': '两个来源的 IP 和国家一致。城市与时区为 IP 地理数据库建议，请确认后保存。'}
