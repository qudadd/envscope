"""Optional anonymous HTTPS observations; no cookies, credentials or user data."""
from concurrent.futures import ThreadPoolExecutor
from .baseline import DOMAINS
from .model import Finding, Status
from .transport import response_evidence

ENDPOINTS = tuple('https://' + domain + '/' for domain in DOMAINS
                  if domain not in ('claude.ai', 'claude.com', 'anthropic.com'))


def observe(transport):
    def one(url):
        return response_evidence(url, transport.get(url, headers_only=True))
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(one, ENDPOINTS))


def finding(rows):
    ready = [r for r in rows if r.get('tls_verified') is True and not r.get('error')
             and type(r.get('http_status')) is int and 100 <= r['http_status'] <= 599]
    complete = len(rows) == len(ENDPOINTS) and {r.get('endpoint') for r in rows} == set(ENDPOINTS)
    certificate_failure = any(r.get('tls_verified') is False for r in rows)
    return Finding('extra.ecosystem', '外围服务 HTTPS 连接',
                   Status.FAIL if certificate_failure else Status.PASS if complete and len(ready) == len(ENDPOINTS) else Status.WARN if ready else Status.UNKNOWN,
                   f'{len(ENDPOINTS)} 个固定端点中，{len(ready)} 个取得经证书校验的 HTTP 响应',
                   'anonymous-https-response-only', rows,
                   ['仅检查所列端点的 HTTPS 回应；HTTP 403/404 也只证明连接回应，不证明登录、支付、验证码或服务功能可用。'],
                   '在实际 Claude 中复查受影响的功能；先核对端点的网络与证书错误，再复检。')
