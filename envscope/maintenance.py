"""Persistent native checks and opt-in, narrowly scoped config drift recovery.

The scheduled worker never switches accounts, installs a proxy, elevates or
executes upstream installers. Explicitly approved watchdog baselines are separate.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import threading
import subprocess
import sys

from .config_files import load_object
from .model import Finding, Status, make_report, utc_now
from .remedies import ConfigRemedies, SolutionPlans, _read, _safe, validate_guard, digest
from .report import redact, diff_reports
from .scheduler import INTERVALS, UserScheduler
from .state import StateStore
from .transport import CurlTransport


def age(value):
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(value)).total_seconds()
    except (TypeError, ValueError):
        return None


def fingerprint(settings):
    return hashlib.sha256(json.dumps(settings, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def proxy_works(proxy):
    response = CurlTransport(proxy).get("https://api.anthropic.com/v1/models")
    return response.status in (200, 401) and response.tls_verified is True and not response.error


class Maintenance:
    def __init__(self, store, remedies=None, scheduler=None, auditor=None, proxy_tester=None, home=None, watchdog=None, timezone_service=None):
        self.store = store
        self.home = Path(home).resolve() if home else Path.home().resolve()
        self.root = store.root / "maintenance"
        self.data = StateStore(self.root, memory=store.memory)
        self.remedies = remedies or ConfigRemedies(self.home, self.home / "Library/Application Support/Claude")
        self.scheduler = scheduler or UserScheduler(self.home, self.root)
        self.auditor, self.proxy_tester = auditor, proxy_tester or proxy_works
        from .watchdog import Watchdog
        self.watchdog=watchdog or Watchdog(self.home)
        self.timezone_service=timezone_service
        self.plans, self.memory = {}, {}
        self.mutex = threading.Lock()

    def _read(self, name, fallback):
        if self.data.memory:
            return self.memory.get(name, fallback)
        body = _read(self.root / (name + ".private.json"))
        return load_object(body.decode("utf-8")) if body is not None else fallback

    def _write(self, name, value):
        if self.data.memory:
            self.memory[name] = value
        else:
            _safe(self.root)
            self.data._write(name + ".private.json", value)

    @contextmanager
    def _lock(self):
        # Use a different OS lock from configuration writes. The latter still
        # serializes foreground fixes and background edits to the actual file.
        if self.data.memory:
            if not self.mutex.acquire(blocking=False):
                raise ValueError("持续维护正在执行")
            try:
                yield
            finally:
                self.mutex.release()
            return
        _safe(self.root).mkdir(parents=True, exist_ok=True, mode=0o700)
        path = _safe(self.root / ".maintenance.lock")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "r+b") as file:
            if not os.fstat(file.fileno()).st_size:
                file.write(b"0")
                file.flush()
            file.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ValueError("持续维护正在执行；请等待本轮结束后重试") from None
            try:
                yield
            finally:
                file.seek(0)
                if os.name == "nt":
                    msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(file.fileno(), fcntl.LOCK_UN)

    def _config(self):
        config = self._read("config", {})
        if not config:
            return {}
        if (not isinstance(config, dict) or type(config.get("version")) is not int or config.get("version") != 1 or type(config.get("enabled")) is not bool
                or type(config.get("auto_restore")) is not bool or type(config.get("interval")) is not int
                or config["interval"] not in INTERVALS or not isinstance(config.get("schedule"), dict)
                or not isinstance(config["schedule"].get("body"), str) or len(config["schedule"]["body"]) > 65536):
            raise ValueError("维护方案无效，自动恢复未执行；请重新生成方案")
        if config["auto_restore"]:
            validate_guard(config.get("approved"))
        self.watchdog.validate(config.get('watchdog',{}))
        return config

    def _event(self, kind, text, **details):
        events = self._read("events", [])
        if not isinstance(events, list):
            events = []
        event={"at": utc_now(), "kind": kind, "text": text, **details}
        if not self.data.memory:
            from .event_log import append_event
            append_event(self.root/'events',event)
        self._write("events", (events + [event])[-100:])

    def prepare(self, report, interval=15, auto_restore=False, watchdog=None):
        if type(interval) is not int or interval not in INTERVALS or type(auto_restore) is not bool:
            raise ValueError("请选择 5、15 或 60 分钟，以及明确的配置保持选项")
        if not SolutionPlans._current(report):
            return {"state": "retest_required", "reason": "先完成一次新的本机检测，再生成长期维护方案。"}
        approved, file_hash = {}, None
        if auto_restore:
            if any(f['id']=='target.region' and f['status']=='fail' for f in report.get('findings',[])):
                return {'state':'blocked','reason':'官方地区条件不合格，不启用自动配置恢复；仍可选择只读巡检。'}
            approved, file_hash = self.remedies.capture_guard()
            proxy = approved.get("HTTPS_PROXY") or approved.get("https_proxy")
            if proxy and self.proxy_tester(proxy) is not True:
                return {"state": "blocked", "reason": "基线代理的 API TLS 连接尚未验证，不启用自动配置恢复。先测试并修复代理。"}
        baseline,guard_effects={},[]
        timezone_plan=None
        if watchdog:
            from .regions import region_finding, PARTIAL
            if (not self.store.settings().get('environment_confirmed') or not self.store.settings().get('usage_country')
                    or region_finding([],self.store.settings()).status==Status.FAIL
                    or self.store.settings().get('usage_country') in PARTIAL
                    or not any(f['id']=='target.region' and f['status']=='pass' for f in report.get('findings',[]))):
                return {'state':'blocked','reason':'请先确认官方支持的实际地区，并修复环境后保存守护基线。'}
            baseline,guard_effects=self.watchdog.prepare(self.store.settings(),watchdog)
            if baseline.get('timezone') and self.timezone_service and self.timezone_service.system=='Darwin':
                status=self.timezone_service.status()
                if not (status.get('installed') and status.get('registered') and status.get('owner')
                        and status.get('target')==baseline['timezone'] and not status.get('needs_update')
                        and status.get('state') in ('active','waiting')):
                    timezone_plan=self.timezone_service.prepare(report)
                    if timezone_plan.get('state')!='planned':return timezone_plan
                    guard_effects.extend(timezone_plan['effects'])
                    guard_effects.append('若后续用户巡检任务注册失败，撤销本次时区服务操作并读回旧基线；可能再次请求系统授权，取消时保留恢复入口。')
        schedule = self.scheduler.build(interval)
        previous = self._config()
        current = self.scheduler.inspect(previous.get("schedule"))
        if current.get("present") is None or current.get("present") and not current.get("owned"):
            return {"state": "blocked", "reason": "同名后台任务存在冲突或无法核对权限；不会覆盖，请先处理任务状态。"}
        effects = [f"为当前用户注册每 {interval} 分钟一次的原生巡检，登录后由系统调度；退出 EnvScope 页面后仍可运行",
                   "每轮联系已列出的公共诊断端点，保存本机脱敏结果和 48 小时出口变化；完整事件按日追加到本机日志，界面展示最近记录",
                   "后台不提权、不安装程序、不切换账号、不停止 Claude；仅执行下方明确批准的恢复动作",
                   "后台不测浏览器 ICE、浏览器扩展或账号登录，使用前仍可点击一键检测"]
        if auto_restore:
            effects.extend(["仅保持 Claude Code 用户配置中的以下 5 个字段；其他配置按当前文件保留",
                            "字段变化后先备份，再恢复批准值；配置删除、格式损坏、基线代理不可用时停止自动恢复",
                            "24 小时最多自动恢复 3 次，反复变化后暂停恢复并记录原因；更换代理前先停用并重新生成方案",
                            "原文件备份可能含认证信息，仅存本机 ~/.envscope/config-backups；撤销前先停用维护"])
            effects.extend(key + "：" + ("保持未设置，新出现时移除" if value is None else value) for key, value in approved.items())
        effects.extend(guard_effects)
        if baseline:effects.append('守护每项至少间隔 5 分钟、24 小时最多尝试恢复 3 次；失败留痕，反复漂移暂停并提示重新审核')
        token = secrets.token_urlsafe(20)
        self.plans = {token: {"deadline": time.monotonic() + 90, "report_id": report["report_id"],
                              "settings_hash": fingerprint(self.store.settings()), "file_hash": file_hash,"timezone_plan":timezone_plan,
                              "config": {"version": 1, "enabled": False, "interval": interval, "auto_restore": auto_restore,
                                         "approved": approved, "watchdog":baseline,"schedule": schedule, "created_at": utc_now()}}}
        return {"state": "planned", "plan_id": token, "effects": effects,
                "reason": "审核后确认启用。开发或试用不会自动替你安装后台任务。"}

    def enable(self, token, report, confirmed=False):
        if confirmed is not True:
            return {"state": "confirmation_required"}
        plan = self.plans.get(token) if isinstance(token, str) else None
        if (not plan or time.monotonic() > plan["deadline"] or not SolutionPlans._current(report)
                or plan["report_id"] != report.get("report_id") or plan["settings_hash"] != fingerprint(self.store.settings())):
            return {"state": "retest_required", "reason": "检测、设置或方案已变化，请重新检测并生成维护方案。"}
        config = plan["config"]
        if config["auto_restore"] and digest(_read(self.remedies.paths["cli"]) or b"") != plan["file_hash"]:
            return {"state": "retest_required", "reason": "Code 配置在预览后变化，未启用旧基线。"}
        if config.get('watchdog') and not self.watchdog.unchanged(config['watchdog']):
            return {'state':'retest_required','reason':'守护基线在预览后变化，请重新检测并生成方案。'}
        with self._lock():
            del self.plans[token]
            previous = self._config()
            config = {**config, "settings_hash": plan["settings_hash"]}
            root_plan=plan.get('timezone_plan')
            if root_plan:
                result=self.timezone_service.apply(root_plan['plan_id'],True)
                if result['state']!='completed':
                    try:self._event('timezone_service',result.get('reason','系统时区服务操作已返回'),state=result['state'],nonce=root_plan['transaction_nonce'])
                    except (OSError,ValueError):pass  # Root-owned transaction evidence remains authoritative.
                    return {'state':'partial','reason':'系统时区守护未完成，尚未启用本次巡检。'+result.get('reason',''),
                            'timezone_service':result,'needs_retest':True}
            elif config.get('watchdog',{}).get('timezone') and self.timezone_service and self.timezone_service.system=='Darwin':
                root_status=self.timezone_service.status()
                if not (root_status.get('installed') and root_status.get('registered') and root_status.get('owner')
                        and root_status.get('target')==config['watchdog']['timezone'] and not root_status.get('pending')):
                    return {'state':'retest_required','reason':'系统时区守护在预览后变化，请重新生成维护方案。'}
            # Fail closed: a registered job cannot repair until enabled is saved.
            try:
                self._write("config", config)
                if root_plan:self._event('timezone_service',result.get('reason','系统时区服务已安装'),state=result['state'],nonce=root_plan['transaction_nonce'])
                self.scheduler.install(config["schedule"], previous.get("schedule"))
            except (OSError, ValueError):
                if root_plan:
                    try:
                        restored=self.timezone_service.rollback_latest(root_plan['transaction_nonce'],True,
                                                                      unchanged_signature=root_plan['before_signature'])
                    except (OSError,ValueError,subprocess.SubprocessError):
                        restored={'state':'partial','reason':'系统时区服务回滚未完整确认，请使用恢复入口核对。'}
                    try:
                        self._event('timezone_service_compensation','用户任务注册失败后的系统时区服务回滚',state=restored['state'])
                    except (OSError,ValueError):
                        restored={**restored,'reason':restored.get('reason','')+' 用户巡检日志未能写入，系统服务备份与日志仍保留。'}
                    return {'state':'failed' if restored['state']=='completed' else 'partial','timezone_service':restored,
                            'needs_retest':True,'reason':'用户巡检任务未确认注册，未启用本次自动恢复。'+restored.get('reason','')}
                self._event("schedule_failed", "后台注册未确认，持续维护和配置自动恢复保持停用。")
                return {"state": "failed", "reason": "系统未确认后台任务注册成功。未启用自动恢复，请检查任务权限后重新生成方案。"}
            if config.get('watchdog'):
                approved={k:v for k,v in config['watchdog'].items() if k!='proxy'}
                if 'proxy' in config['watchdog']:
                    p=config['watchdog']['proxy'];approved['proxy']={k:p[k] for k in ('url','group','node') if k in p}
                    if p.get('client'):approved['proxy']['client']={k:p['client'][k] for k in ('label','path','sha256')}
                self._event('watchdog_approved','已明确批准本次守护基线',approved=approved,interval=config['interval'])
            config["enabled"] = True
            self._write("config", config)
            self._write("stats", {"repair_times": [], "repair_paused": False})
            self._event("enabled", "已启用持续维护；等待系统首次运行，尚不能报告巡检成功。")
        return {"state": "enabled", "reason": "后台任务已注册。可以立即复检验证执行，或等待系统调度；请保留当前应用目录。"}

    def disable(self, confirmed=False):
        if confirmed is not True:
            return {"state": "confirmation_required"}
        with self._lock():
            config = self._config()
            if config:
                config["enabled"] = False
                self._write("config", config)
            try:
                self.scheduler.remove(config.get("schedule"))
                note='已单独授权的 macOS 系统时区守护需在下方预览停用；本次不改系统时区。' if self.timezone_service and self.timezone_service.system=='Darwin' else '不恢复系统设置。'
                result = {"state": "disabled", "reason": "持续维护已停用，用户巡检任务已移除。保留检测记录和私有备份。"+note}
            except (OSError, ValueError):
                result = {"state": "partial", "reason": "自动恢复已停用，但系统任务未确认移除。保留任务文件供核对；后台再次唤起也不会执行恢复。"}
            self._event("disabled", result["reason"])
        return result

    def status(self):
        try:
            config = self._config()
            stats = self._read("stats", {})
            latest = self._read("latest", None)
            events = self._read("events", [])
            if not isinstance(stats, dict) or not isinstance(events, list):
                raise ValueError("invalid maintenance records")
            if latest is not None and not isinstance(latest, dict):
                raise ValueError("invalid last report")
            scheduler = self.scheduler.inspect(config.get("schedule"))
            elapsed = age(stats.get("completed_at"))
            enabled = config.get("enabled") is True
            waiting_age = age(config.get("created_at"))
            waiting_state = "stale" if waiting_age is None or waiting_age < 0 or waiting_age > config.get("interval", 15) * 60 + 180 else "waiting"
            state = ("disabled" if not enabled else "schedule_unverified" if not scheduler.get("registered") else "failed" if stats.get("last_state") == "failed"
                     else waiting_state if elapsed is None else "stale" if elapsed < 0 or elapsed > config["interval"] * 60 + 180
                     else "attention" if config.get("auto_restore") and stats.get("restore_state") in ("blocked", "unverified", "paused") or any(r.get('state') in ('attention','paused','cooldown','delegated') for r in stats.get('watchdog',{}).values()) else "active")
            events = [dict(event) for event in events[-20:] if isinstance(event, dict)]
            for event in events:
                if not isinstance(event.get("backups", []), list):
                    raise ValueError("invalid backup records")
                event["backups"] = [{**backup, "availability": self.remedies.backup_status(backup.get("id"))}
                                    for backup in event.get("backups", []) if isinstance(backup, dict)]
            return {"state": state, "enabled": enabled, "interval": config.get("interval", 15),
                    "auto_restore": config.get("auto_restore", False), "repair_paused": stats.get("repair_paused", False),
                    "watchdog":stats.get('watchdog',{}),"watchdog_enabled":bool(config.get('watchdog')),
                    "journal_path":str(self.root/'events'),
                    "scheduler": scheduler, "completed_at": stats.get("completed_at"),
                    "started_at": stats.get("started_at"), "last_state": stats.get("last_state"),
                    "restore_state": stats.get("restore_state"), "restore_note": stats.get("restore_note", ""),
                    "problem_count": len((latest or {}).get("diagnosis", {}).get("problems", [])),
                    "egress_48h": stats.get("egress_48h", {"observations": 0, "changes": 0}),
                    "events": events, "has_report": isinstance(latest, dict),
                    "reason": "后台仅复检原生项目；浏览器、登录和权威 DNS 出口未被自动验证。"}
        except (ValueError, OSError, UnicodeError, TypeError, AttributeError):
            return {"state": "invalid", "enabled": False, "events": [], "reason": "维护记录无法读取或路径不安全，未报告维护正常；请核对本机文件。"}

    def latest_report(self):
        value = self._read("latest", None)
        return {"state": "completed" if value else "missing", "report": value,
                "reason": "这是最近一次后台原生巡检，不包含新的浏览器或账号登录证明。"}

    def _restore(self, config, stats):
        def mark(state, note):
            stats.update(restore_state=state, restore_note=note)
        if not config["auto_restore"]:
            mark("off", "本方案只读巡检，未选择自动配置恢复。")
            return
        if stats.get("repair_paused"):
            mark("paused", "配置恢复已暂停；需核对原因并审核新方案，巡检仍继续。")
            return
        if config.get("settings_hash") != fingerprint(self.store.settings()):
            stats["repair_paused"] = True
            mark("paused", "设置已改变，暂停旧基线恢复；请审核新的维护方案。")
            self._event("restore_paused", "比较或启动设置已改变，暂停旧配置基线恢复；请审核新的维护方案。")
            return
        try:
            change = self.remedies.preview_guard(config["approved"])
            if not change:
                mark("in_sync", "批准的 Code 字段本轮未发生变化。")
                return
            times = stats.get("repair_times", [])
            if not isinstance(times, list):
                raise ValueError("invalid repair history")
            if any(age(t) is None or age(t) < 0 for t in times):
                stats["repair_paused"] = True
                mark("paused", "恢复时间记录无法核实，暂停自动恢复。")
                self._event("restore_paused", "恢复次数的时间记录无法核实，暂停自动恢复；请核对系统时间并审核新方案。")
                return
            times = [t for t in times if age(t) is not None and 0 <= age(t) < 86400]
            if len(times) >= 3:
                stats["repair_paused"] = True
                mark("paused", "24 小时已恢复 3 次；反复变化，暂停恢复。")
                self._event("restore_paused", "24 小时已恢复 3 次；配置反复变化，已暂停自动恢复，请检查其他配置管理工具。")
                return
            proxy = config["approved"].get("HTTPS_PROXY") or config["approved"].get("https_proxy")
            if proxy and self.proxy_tester(proxy) is not True:
                mark("blocked", "基线代理未通过 API TLS 探测，本轮没有恢复配置。")
                self._event("restore_blocked", "批准的基线代理未通过 API TLS 探测，未恢复配置；不会回退直连。")
                return
            result = self.remedies.apply([change])
            if result["backups"]:
                stats["repair_times"] = times + [utc_now()]
            if result["state"] == "completed" and self.remedies.preview_guard(config["approved"]) is None:
                mark("restored", "本轮已备份并恢复批准字段，字段复核通过。")
                self._event("restored", "已备份并恢复批准的 Code 字段，字段复核通过；需按客户端行为重新加载。",
                            keys=change["keys"], backups=result["backups"])
            else:
                mark("unverified", "本轮配置恢复未确认完成；请保留备份并复检。")
                self._event("restore_unverified", "配置恢复未确认完成；保留备份，需人工复检。", backups=result["backups"])
        except (OSError, ValueError, UnicodeError):
            mark("blocked", "Code 配置或备份不能安全写入，本轮没有确认恢复完成；请手动复检。")
            self._event("restore_blocked", "配置已删除、格式异常、发生并发修改或备份不可写，未覆盖文件；请先复检。")

    def run_once(self):
        from .probes import audit
        with self._lock():
            config = self._config()
            if not config.get("enabled"):
                return {"state": "disabled", "reason": "持续维护未启用，未运行探测或修改配置。"}
            stats = self._read("stats", {})
            if not isinstance(stats, dict):
                raise ValueError("维护记录异常，未执行自动恢复")
            stats["started_at"] = utc_now()
            self._write("stats", stats)
            try:
                preferences = self.store.settings()
                policy = self.store.policy()
                from .transport import desktop_transport
                findings = (self.auditor or audit)(policy, desktop_transport(preferences), online=True, stun=True, ipv6=True,
                                                   browser=None, baseline_config=preferences)
                from .regions import region_finding
                region = region_finding(findings,preferences)
                watchdog_changed=False
                if (config['auto_restore'] or config.get('watchdog')) and region.status == Status.FAIL:
                    stats.update(repair_paused=True,restore_state='paused',restore_note='本轮官方地区条件不合格，已暂停配置恢复；只读巡检继续。')
                    if config.get('watchdog'):
                        stats['watchdog_paused']=True
                        stats['watchdog']={k:{'state':'paused','note':'官方地区条件不合格，自动守护暂停；需重新批准基线'} for k in config['watchdog']}
                    self._event('restore_paused','官方地区条件不合格，未执行自动配置恢复。')
                else:
                    if config.get('watchdog'):
                        if stats.get('watchdog_paused') or config.get('settings_hash')!=fingerprint(preferences):
                            stats['watchdog_paused']=True
                            stats['watchdog']={k:{'state':'paused','note':'目标设置变化，需重新批准守护基线'} for k in config['watchdog']}
                            self._event('watchdog_paused','检测目标已变化，未执行旧守护基线。')
                        else:
                            watchdog_changed=self.watchdog.run(config['watchdog'],stats,self._event,lambda:self._write('stats',stats))
                    self._restore(config,stats)
                    if watchdog_changed or stats.get('restore_state') in ('restored','unverified'):
                        findings = (self.auditor or audit)(policy, desktop_transport(preferences), online=True, stun=True, ipv6=True,
                                                           browser=None, baseline_config=preferences)
                signature, key = self.data._signature([f.to_dict() for f in findings])
                self.data._write("history-key.private.json", key)
                comparison_key = hashlib.sha256(bytes.fromhex(key)).hexdigest()
                timeline = self._read("egress", [])
                if not isinstance(timeline, list):
                    timeline = []
                timeline = [x for x in timeline if isinstance(x, dict) and isinstance(x.get("signature"), str) and x.get("comparison_key") == comparison_key
                            and age(x.get("at")) is not None and 0 <= age(x.get("at")) < 172800][-599:]
                previous = timeline[-1]["signature"] if timeline else None
                if signature:
                    timeline.append({"at": utc_now(), "signature": signature, "comparison_key": comparison_key})
                    self._write("egress", timeline)
                stats["egress_48h"] = {"observations": len(timeline), "changes": sum(a["signature"] != b["signature"] for a, b in zip(timeline, timeline[1:]))}
                for f in findings:
                    if f.id == "baseline.ip_stability" and signature and previous:
                        f.status = Status.WARN if signature != previous else Status.PASS
                        f.summary = "出口集合与上次后台有效观测不同" if signature != previous else "出口集合与上次后台有效观测相同"
                        f.scope = "scheduled-native-observations"
                findings.append(Finding("maintenance.browser", "浏览器与登录状态", Status.SKIPPED,
                                        "后台不使用历史 ICE 冒充当前浏览器观测；账号登录未测", "scheduled-native-only"))
                raw = make_report(findings, policy, "scheduled-native", preferences)
                safe = redact(raw)
                previous_report = self._read("latest", None)
                if previous_report:
                    changes = diff_reports(previous_report, safe)
                    if changes:
                        self._event("checks_changed", "原生检测状态发生变化；已保存本轮结果。", changes=changes)
                self._write("latest", safe)
                stats.update(completed_at=utc_now(), last_state="completed")
                self._event("checked", f"本轮原生巡检完成，{len(raw['diagnosis']['problems'])} 个待处理问题；未检测项目仍保留未核实。")
                self._write("stats", stats)
                return {"state": "completed", "reason": "原生巡检已完成；请查看问题、逐项清单及事件。", "report": safe}
            except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
                stats["last_state"] = "failed"
                self._write("stats", stats)
                self._event("failed", "本轮未能完成；上一份结果保留，不能视为本轮通过。")
                return {"state": "failed", "reason": "本轮原生巡检未完成，请在检测页手动复检。"}


def main(argv=None):
    # Fixed, argument-free worker used by both packaged applications and Python.
    args = sys.argv[1:] if argv is None else argv
    if args == ["--check-runtime"]:
        return 0
    if args:
        return 3
    try:
        result = Maintenance(StateStore()).run_once()
        return 0 if result["state"] in ("completed", "disabled") else 2
    except (ValueError, OSError):
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
