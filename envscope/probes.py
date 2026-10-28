from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .browser import assess_snapshot
from .controller import inspect_controller
from .inventory import collect
from .model import Finding, Status, utc_now
from .network_facts import bounded_facts
from .local_facts import local_snapshot
from .extended import extended_checks, add_guidance
from .policy import assess_addresses, assess_http
from .transport import application_state, display_url, parse_ip_response

ENDPOINTS = {
    4: (("cloudflare-v4", "https://www.cloudflare.com/cdn-cgi/trace", "trace"),
        ("ipify-v4", "https://api4.ipify.org?format=json", "json")),
    6: (("cloudflare-v6", "https://www.cloudflare.com/cdn-cgi/trace", "trace"),
        ("ipify-v6", "https://api6.ipify.org?format=json", "json")),
}
STUN_SERVERS = (("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302))


def http_observations(transport, family):
    def one(endpoint):
        name, url, parser = endpoint
        response = transport.get(url, family)
        result = {"source": name, "endpoint": display_url(url), "family": family,
                  "path": transport.path, "observed_at": utc_now(), "http_status": response.status}
        if getattr(transport, 'proxy', None):
            result['proxy_endpoint'] = display_url(transport.proxy)
        try:
            result["ip"] = parse_ip_response(response, parser, family)
            if parser == "trace":
                fields = dict(line.split("=", 1) for line in response.body.splitlines() if "=" in line)
                if len(fields.get("loc", "")) == 2:
                    result["country"] = fields["loc"]
        except (ValueError, TypeError):
            result["error"] = response.error or "invalid_status_or_ip_payload"
        return result
    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(one, ENDPOINTS[family]))


def stun_observations(family=4, timeout=2):
    def one(server):
        host, port = server
        observation = {"source": host, "port": port, "family": family, "path": "native-udp",
                       "observed_at": utc_now()}
        try:
            with tempfile.TemporaryDirectory(prefix="envscope-stun-") as directory:
                output = Path(directory) / "result.json"
                command = [sys.executable, "--stun-worker"] if getattr(sys, "frozen", False) else [sys.executable, "-m", "envscope._stun_worker"]
                command.extend([host, str(port), str(family), str(timeout), str(output)])
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 3,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                value = json.loads(output.read_text()) if result.returncode == 0 and output.exists() and output.stat().st_size < 1024 else {}
            if isinstance(value, dict):
                observation.update({k: value[k] for k in ("ip", "error") if k in value})
            if "ip" not in observation and "error" not in observation:
                observation["error"] = "invalid_worker_result"
        except (subprocess.TimeoutExpired, OSError, ValueError):
            observation["error"] = "deadline_or_unavailable"
        return observation
    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(one, STUN_SERVERS))


def audit(policy, transport, online=False, stun=False, ipv6=False, targets=(), browser=None, controller=None, secret=None, baseline_config=None):
    with ThreadPoolExecutor(max_workers=6) as pool:
        inventory_job = pool.submit(collect)
        facts_job = pool.submit(bounded_facts) if online else None
        v4_job = pool.submit(http_observations, transport, 4) if online else None
        v6_job = pool.submit(http_observations, transport, 6) if online and ipv6 else None
        udp4_job = pool.submit(stun_observations, 4) if online and stun else None
        udp6_job = pool.submit(stun_observations, 6) if online and stun and ipv6 else None
        inventory = inventory_job.result()
        network = facts_job.result() if facts_job else {"dns": [], "routes": []}
        v4, v6 = v4_job.result() if v4_job else [], v6_job.result() if v6_job else []
        udp = (udp4_job.result() if udp4_job else []) + (udp6_job.result() if udp6_job else [])
    findings = [
        Finding("system.inventory", "系统只读信息采集", Status.UNKNOWN if "network_error" in inventory or inventory.get("network", {}).get("errors") else Status.PASS,
                "系统信息已采集；虚拟网卡和进程存在均不是接管证明", "native-inventory", [inventory]),
        Finding("network.route", "目标流量接管验证", Status.UNKNOWN, "当前只记录路由配置，尚未完成目标进程流量关联",
                "native-inventory", limitations=["默认路由、TUN 名称或 Fake-IP 不能单独证明目标流量没有旁路。"]),
    ]
    findings.extend([assess_http(v4, policy, 4), assess_http(v6, policy, 6)])
    findings.append(assess_addresses("udp.stun", "原生 UDP STUN 出口", udp, policy,
                                     [o["ip"] for o in v4 + v6 if "ip" in o], "native-udp", minimum=2))
    findings[-1].limitations.extend(["原生 UDP 不继承 HTTP 代理，不代表浏览器 WebRTC。", "无响应可能来自阻断、故障或服务不可用，不能证明零暴露。"])
    findings.append(Finding("dns.leak", "DNS 实际解析出口", Status.UNKNOWN,
                            "尚无权威 DNS 随机域名观测，系统 DNS 配置不能作为无泄漏证明", "dns-authoritative",
                            limitations=["DoH 可达、解析到 Fake-IP、HTTP 出口一致都不能替代权威侧解析源观测。",
                                         "权威 DNS 收集服务列入后续版本，首版不伪造通过。" ]))
    findings.append(assess_snapshot(browser, policy))
    if baseline_config is not None:
        from .baseline import collect_baseline
        context = {}
        with ThreadPoolExecutor(max_workers=2) as pool:
            local_job = pool.submit(local_snapshot, inventory)
            baseline = collect_baseline(inventory, v4, v6, findings[-3], findings[-1], baseline_config, transport, online, context)
            local = local_job.result()
        findings.extend(baseline)
        findings.extend(extended_checks(inventory, network, local, context))
    if controller:
        findings.append(inspect_controller(controller, secret))
    for index, url in enumerate(targets):
        response = transport.get(url)
        state = application_state(response)
        status = Status.UNKNOWN if response.error else Status.PASS if state == "http_success_only" else Status.WARN
        findings.append(Finding("target." + str(index + 1), "目标 HTTP 响应", status,
                                "已收到 HTTP 成功响应；未验证登录或应用功能" if state == "http_success_only" else state,
                                transport.path, [{"endpoint": display_url(url), "http_status": response.status,
                                                  "application_state": state, "transport_error": response.error}],
                                ["无认证 GET 请求，不跟随重定向；403、429 和 5xx 不记为应用可用。" ]))
    return add_guidance(findings)
