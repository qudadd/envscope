"""Reassess user-supplied browser observations; never trust imported verdicts."""
from datetime import datetime, timezone
import json
from pathlib import Path

from .model import Finding, Status
from .policy import assess_addresses, normalize_ip, public_ip


def load_snapshot(path):
    file = Path(path)
    if file.stat().st_size > 1048576:
        raise ValueError("browser snapshot too large")
    raw = json.loads(file.read_text(encoding="utf-8-sig"))
    return validate_snapshot(raw)


def validate_snapshot(raw):
    if (not isinstance(raw, dict) or raw.get("schema_version") != 1
            or raw.get("kind") != "envscope-browser-observations"):
        raise ValueError("not an EnvScope browser observation snapshot")
    if not isinstance(raw.get("http"), list) or not isinstance(raw.get("ice"), list):
        raise ValueError("browser snapshot is missing observation arrays")
    if len(raw["http"]) > 8 or len(raw["ice"]) > 128:
        raise ValueError("too many browser observations")
    if any(not isinstance(o, dict) for o in raw["http"] + raw["ice"]):
        raise ValueError("invalid browser observation shape")
    if not isinstance(raw.get("created_at"), str) or len(raw["created_at"]) > 64:
        raise ValueError("invalid browser timestamp")
    if not isinstance(raw.get("contains_sensitive"), bool) or not isinstance(raw.get("ice_complete"), bool):
        raise ValueError("invalid browser observation flags")
    for obs in raw["http"]:
        if not isinstance(obs.get("source"), str) or len(obs["source"]) > 64 or ("ip" in obs and not isinstance(obs["ip"], str)):
            raise ValueError("invalid browser HTTP observation")
    for candidate in raw["ice"]:
        if (not isinstance(candidate.get("type"), str) or not isinstance(candidate.get("address"), str)
                or len(candidate["address"]) > 255):
            raise ValueError("invalid ICE observation")
    return raw


def assess_snapshot(snapshot, policy, now=None):
    unknown = lambda summary: Finding("browser.webrtc", "浏览器 WebRTC 候选观测", Status.UNKNOWN, summary,
                                      "browser-user-supplied-snapshot", limitations=["导入文件不是签名证据；不代表其他浏览器或桌面应用。"])
    if snapshot is None:
        return unknown("尚未导入当前浏览器的原始观测")
    try:
        created = datetime.fromisoformat(snapshot["created_at"].replace("Z", "+00:00"))
        if created.tzinfo is None:
            return unknown("浏览器观测缺少带时区的时间戳")
        age = ((now or datetime.now(timezone.utc)) - created).total_seconds()
        if age < -30 or age > 300:
            return unknown("浏览器观测超出 5 分钟窗口或来自未来，需要重新检测")
    except (ValueError, TypeError, KeyError):
        return unknown("浏览器观测时间戳无效")
    if snapshot.get("contains_sensitive") is not True:
        return unknown("分享版已去除原始地址；可展示，但不能用于重新比对地址")
    http, http_sources = [], {4: set(), 6: set()}
    for obs in snapshot["http"]:
        if obs.get("source") not in ("ipify-v4", "cloudflare-v4", "ipify-v6", "cloudflare-v6"):
            continue
        try:
            address = public_ip(obs.get("ip"))
            family = normalize_ip(address).version
            if not obs["source"].endswith("-v" + str(family)):
                continue
            http.append(address)
            http_sources[family].add(obs["source"])
        except (ValueError, TypeError):
            pass
    candidates = []
    for candidate in snapshot["ice"]:
        if candidate.get("type") not in ("host", "srflx", "prflx"):
            continue
        try:
            address = public_ip(candidate.get("address"))
        except (ValueError, TypeError):
            continue
        candidates.append({"ip": address, "source": "browser-ice", "candidate_type": candidate["type"]})
    result = assess_addresses("browser.webrtc", "浏览器 WebRTC 候选观测", candidates, policy, http,
                              "browser-user-supplied-snapshot")
    result.limitations.extend(["TURN relay 地址不作为客户端公网地址。", "数据通道观测不申请麦克风权限，接口覆盖可能受浏览器策略限制。",
                               "导入文件由用户提供，未签名且未与本次原生测量绑定；不能用于可信远程审计。"])
    if snapshot.get("ice_complete") is not True and result.status != Status.FAIL:
        result.status = Status.UNKNOWN
        result.summary = "ICE 收集未完成，不能给出通过结论"
    elif result.status == Status.PASS:
        needs_baseline = {normalize_ip(c["ip"]).version for c in candidates
                          if not policy.networks_for(normalize_ip(c["ip"]).version)}
        if any(len(http_sources[family]) < 2 for family in needs_baseline):
            result.status = Status.WARN
            result.summary = "候选与已观测地址相符，但独立 HTTP 对照不足"
    return result


def environment_finding(snapshot, now=None):
    """Whitelisted browser metadata, scoped to this window and 5 minute sample."""
    info, fresh = {}, False
    try:
        created = datetime.fromisoformat(snapshot['created_at'].replace('Z','+00:00'))
        age = ((now or datetime.now(timezone.utc))-created).total_seconds()
        fresh = -30 <= age <= 300
        raw = snapshot.get('environment', {})
        if not isinstance(raw, dict):
            raw = {}
        for key in ('timezone','platform','renderer','vendor'):
            if isinstance(raw.get(key),str) and 0 < len(raw[key]) <= 256:
                info[key] = raw[key]
        for key in ('automated','canvas_available'):
            if type(raw.get(key)) is bool:
                info[key] = raw[key]
        for key in ('hardware_threads','screen_width','screen_height','color_depth'):
            if type(raw.get(key)) is int and 0 < raw[key] <= 65536:
                info[key] = raw[key]
        if isinstance(raw.get('languages'),list):
            info['languages'] = [v for v in raw['languages'][:16] if isinstance(v,str) and 0<len(v)<=64]
    except (KeyError, TypeError, ValueError, AttributeError):
        pass
    usable = fresh and bool(info.get('timezone')) and bool(info.get('languages'))
    return Finding('browser.environment','当前浏览器环境资料',Status.PASS if usable else Status.UNKNOWN,
                   '已记录本窗口的时区、语言及可取得的设备资料' if usable else '尚未取得新鲜、完整的浏览器环境资料',
                   'current-browser-self-reported-metadata', [info] if fresh else [],
                   ['浏览器可限制或修改这些值；不代表 Claude Electron 或其他浏览器。',
                    '不保存 Canvas 摘要，不收集行为时序；原始 Canvas 摘要仅在工具页本地按需查看。',
                    '自动化、中文、虚拟 GPU 和屏幕差异均不是账号风险判据。'],
                   '使用你实际运行 Claude 的浏览器重新检测；被浏览器限制的属性无需关闭隐私保护来获取。')
