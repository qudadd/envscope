"""Reviewed, fixed-target configuration edits with private backups and undo.

No shell strings, arbitrary paths, credential installation, automatic system
network edits or repairs inferred from an untrusted imported report.
"""
from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time

from .config_files import inspect_text, remove_trailing_commas
from .discovery import safe_local_proxy

MAX_CONFIG = 1048576
LABELS = {"desktop": "Claude 桌面配置", "cli": "Claude Code 用户配置"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _safe(path):
    """Reject links/reparse points in every existing component of a fixed path."""
    path = Path(os.path.abspath(path))
    for candidate in reversed([path, *path.parents]):
        try:
            mode = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 0x400:
            raise ValueError("配置路径包含链接或重解析点，未执行写入")
    return path


def _read(path):
    path = _safe(path)
    try:
        with path.open("rb") as file:
            value = file.read(MAX_CONFIG + 1)
        if len(value) > MAX_CONFIG:
            raise ValueError("配置文件超出可处理大小")
        return value
    except FileNotFoundError:
        return None


def _replace(path, data, expected):
    path = _safe(path)
    if _read(path) != expected:
        raise ValueError("配置在预览后发生变化，未覆盖，请重新生成方案")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _safe(path.parent)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    handle, name = tempfile.mkstemp(prefix=".envscope-edit-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        temporary.chmod(mode)
        # Recheck immediately before replacing; never dereference a new link.
        if _read(path) != expected:
            raise ValueError("配置在写入前发生变化，原文件已保留")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _without_targets(value):
    patterns = [p for p in re.split(r"[,;\s]+", value) if p]
    from .local_facts import bypass_matches
    return ",".join(p for p in patterns if not bypass_matches(p)["target_matches"])


class ConfigRemedies:
    def __init__(self, home, profile, environ=None):
        home_path = Path(os.path.abspath(home))
        # Canonicalize the trusted home root (including macOS /var temp aliases),
        # but never resolve untrusted configuration children before checking them.
        self.home = home_path.resolve()
        profile_path = Path(os.path.abspath(profile))
        if profile_path.is_relative_to(home_path):
            profile_path = self.home / profile_path.relative_to(home_path)
        self.paths = {"desktop": profile_path / "claude_desktop_config.json", "cli": self.home / ".claude/settings.json"}
        self.backups = self.home / ".envscope/config-backups"
        self.environ = os.environ if environ is None else environ
        self.undo_records = {}

    @contextmanager
    def _lock(self):
        _safe(self.backups).mkdir(parents=True, exist_ok=True, mode=0o700)
        path = _safe(self.backups / ".repair.lock")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "r+b") as file:
            if os.fstat(file.fileno()).st_size == 0:
                file.write(b"0")
                file.flush()
            file.seek(0)
            acquired = False
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as error:
                raise ValueError("另一个配置修复正在进行，请稍后复检") from error
            try:
                yield
            finally:
                if acquired:
                    file.seek(0)
                    if os.name == "nt":
                        msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(file.fileno(), fcntl.LOCK_UN)

    def backup_for_editor(self, target):
        if target not in self.paths:
            raise ValueError("未知配置文件")
        original = _read(self.paths[target])
        if original is None:
            raise ValueError("配置文件尚未创建，无需修复")
        _safe(self.backups).mkdir(parents=True, exist_ok=True, mode=0o700)
        file = self.backups / (secrets.token_urlsafe(18) + ".private.json")
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        if _read(file) != original:
            raise ValueError("备份校验未通过，未打开编辑器")
        metadata = file.with_suffix(".recovery.json")
        fd = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"target": target, "before_hash": digest(original), "editor_backup": True,
                       "created_at": datetime.now(timezone.utc).isoformat()}, stream)
        return self.paths[target]

    def preview(self, target, kinds, proxy=None):
        if target not in self.paths or set(kinds) - {"trailing_comma", "proxy", "tls"}:
            raise ValueError("未知配置修复")
        if target != "cli" and set(kinds) - {"trailing_comma"}:
            raise ValueError("此修复只适用于 Claude Code")
        path = self.paths[target]
        original = _read(path)
        text = original.decode("utf-8-sig") if original is not None else "{}"
        effects = []
        if "trailing_comma" in kinds:
            candidate = remove_trailing_commas(text)
            if candidate is None:
                raise ValueError("当前文件没有可确定修复的多余逗号")
            text = candidate
            effects.append("移除 " + LABELS[target] + " 结尾多余的逗号，保留原有值")
        if inspect_text(text).get("valid") is not True:
            raise ValueError("配置仍存在其他语法或结构问题，未自动改写")
        if set(kinds) & {"proxy", "tls"}:
            data = json.loads(text)
            env = data.setdefault("env", {})
            if "proxy" in kinds:
                chosen = safe_local_proxy(proxy)
                if not chosen or not chosen.startswith(("http://", "https://")):
                    raise ValueError("需要经过验证的本机 HTTP / HTTPS 代理")
                env["HTTPS_PROXY"] = env["https_proxy"] = chosen
                for lower, upper in (("no_proxy", "NO_PROXY"),):
                    existing = env.get(lower) or env.get(upper) or self.environ.get(lower) or self.environ.get(upper, "")
                    env[lower] = env[upper] = _without_targets(existing)
                    if any(any(c in p for c in "*?[") for p in re.split(r"[,;\s]+", existing) if p and _without_targets(p) == ""):
                        effects.append("将移除匹配目标的 NO_PROXY 通配条目；这也可能改变 Code 对其他同类域名的路径")
                effects.append("仅将 Claude Code 的 HTTPS_PROXY / https_proxy 设为 " + chosen)
                effects.append("仅从 Claude Code 的 NO_PROXY / no_proxy 中移除匹配目标域名的条目，保留其他条目")
            if "tls" in kinds:
                env["NODE_TLS_REJECT_UNAUTHORIZED"] = "1"
                effects.append("在 Claude Code 用户配置中恢复 Node TLS 证书校验")
            text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        after = (b"\xef\xbb\xbf" if original and original.startswith(b"\xef\xbb\xbf") else b"") + text.encode("utf-8")
        if len(after) > MAX_CONFIG:
            raise ValueError("修改后的配置超过大小上限，未执行写入")
        if original == after:
            return None
        return {"target": target, "label": LABELS[target], "before": original, "after": after,
                "before_hash": digest(original) if original is not None else None, "after_hash": digest(after), "effects": effects}

    def apply(self, changes):
        with self._lock():
            return self._apply(changes)

    def _apply(self, changes):
        # Validate every target before writing the first one.
        for change in changes:
            if _read(self.paths[change["target"]]) != change["before"]:
                raise ValueError("文件在确认后发生变化，请重新生成修复方案")
        records = []
        try:
            for change in changes:
                path = self.paths[change["target"]]
                token = secrets.token_urlsafe(18)
                _safe(self.backups).mkdir(parents=True, mode=0o700, exist_ok=True)
                backup = self.backups / (token + ".private.json")
                if change["before"] is not None:
                    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as file:
                        file.write(change["before"])
                        file.flush()
                        os.fsync(file.fileno())
                record = {"target": change["target"], "label": change["label"], "backup": backup,
                          "before": change["before"], "after": change["after"], "created_at": datetime.now(timezone.utc).isoformat()}
                # Persist recovery metadata before replacing the original file.
                recovery = self.backups / (token + ".recovery.json")
                metadata = {"target": change["target"], "before_hash": change["before_hash"], "after_hash": change["after_hash"],
                            "original_existed": change["before"] is not None, "created_at": record["created_at"]}
                fd = os.open(recovery, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as file:
                    json.dump(metadata, file)
                    file.flush()
                    os.fsync(file.fileno())
                _replace(path, change["after"], change["before"])
                self.undo_records[token] = record
                records.append({"id": token, "label": change["label"]})
        except (OSError, ValueError):
            # Completed writes remain explicit and individually undoable.
            return {"state": "partial" if records else "failed", "backups": records,
                    "reason": "部分配置未能写入。已保留原文件备份；已完成的项目可撤销，请重新检测。"}
        return {"state": "completed", "backups": records}

    def undo(self, token, confirmed=False):
        if confirmed is not True:
            return {"state": "confirmation_required"}
        with self._lock():
            return self._undo(token)

    def _undo(self, token):
        if not isinstance(token, str) or token not in self.undo_records:
            raise ValueError("该备份不属于本次服务会话")
        record = self.undo_records[token]
        path = self.paths[record["target"]]
        if _read(path) != record["after"]:
            raise ValueError("配置在修复后又被修改，未覆盖。请保留备份并手动合并")
        if record["before"] is not None:
            if _read(record["backup"]) != record["before"]:
                raise ValueError("备份校验不通过，未执行恢复")
            _replace(path, record["before"], record["after"])
        else:
            _safe(path).unlink()
        del self.undo_records[token]
        return {"state": "completed", "label": record["label"], "reason": "已恢复原配置；请重开客户端并复检。"}


class SolutionPlans:
    def __init__(self, config, legacy, discoverer, proxy_tester):
        self.config, self.legacy, self.discoverer, self.proxy_tester = config, legacy, discoverer, proxy_tester
        self.plans = {}

    @staticmethod
    def _current(report):
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(report["created_at"])).total_seconds()
            return 0 <= age < 90 and report.get("mode") == "one-click-desktop" and isinstance(report.get("diagnosis"), dict)
        except (ValueError, KeyError, TypeError):
            return False

    def prepare(self, report):
        if not self._current(report):
            return {"state": "retest_required", "reason": "请先完成一次新的本机一键检测，再生成处理方案。"}
        problems = report["diagnosis"]["problems"]
        tasks, effects, manual, kinds = [], [], [], {}
        for problem in problems:
            repair = problem.get("repair")
            if repair in ("json-desktop", "json-cli"):
                kinds.setdefault(repair.split("-")[1], set()).add("trailing_comma")
            elif repair == "cli-tls":
                kinds.setdefault("cli", set()).add("tls")
        if any(p.get("repair") == "cli-proxy" for p in problems):
            candidates = [p["url"] for p in self.discoverer() if safe_local_proxy(p.get("url")) and p["url"].startswith(("http://", "https://"))]
            chosen = None
            for candidate in list(dict.fromkeys(candidates))[:2]:
                result = self.proxy_tester(candidate)
                # Do not send credentials; API 401 is expected for this probe.
                api = next((e for e in result.get("evidence", []) if e.get("endpoint") == "https://api.anthropic.com/v1/models"), {})
                if api.get("http_status") in (200, 401) and api.get("tls_verified") is True and not api.get("error"):
                    chosen = candidate
                    break
            if chosen:
                kinds.setdefault("cli", set()).add("proxy")
            else:
                manual.append("尚未验证可用的本机 HTTP / HTTPS 代理；请在代理客户端开启 HTTP / mixed 端口，再测试。没有改写 Claude Code 代理。")
        else:
            chosen = None
        changes = []
        for target, edits in kinds.items():
            try:
                change = self.config.preview(target, edits, chosen)
                if change:
                    changes.append(change)
                    effects.extend(change["effects"])
            except (ValueError, OSError, UnicodeError):
                manual.append(LABELS[target] + "不能安全自动修改，请使用该问题的文件入口修正。")
        if changes:
            effects.insert(0, "为将修改的配置创建私有原文件备份与恢复记录，随后仅写入下列字段")
            tasks.append("config")
        if any(p.get("repair") == "legacy" for p in problems):
            caps = self.legacy.capabilities()
            fix = next((a for a in caps["actions"] if a["id"] == "fix"), {})
            install = next((a for a in caps["actions"] if a["id"] == "install"), {})
            if fix.get("available"):
                tasks.append("fix")
                effects.extend(fix["effects"])
            elif install.get("available"):
                tasks.append("install")
                effects.extend(install["effects"])
                manual.append("安装器是交互流程，完成后点击继续复检，以实际安装与运行状态为准。")
            else:
                manual.append("当前平台或已安装维护核心不支持自动修复，按问题列出的步骤处理后复检。")
        if not tasks:
            return {"state": "guided", "effects": [], "manual": manual, "reason": "本次没有可安全自动执行的修改。请按已定位问题的具体步骤处理，再复检。"}
        token = secrets.token_urlsafe(20)
        self.plans = {token: {"deadline": time.monotonic() + 90, "report_id": report["report_id"], "changes": changes,
                              "tasks": tasks, "problems": [p["id"] for p in problems],
                              "before": {"problems": [{"id": p["id"], "title": p["title"]} for p in problems]}}}
        return {"state": "planned", "plan_id": token, "effects": effects, "manual": manual,
                "steps": ["备份并修改确定可处理的配置" if t == "config" else "运行维护核心修复" if t == "fix" else "打开维护核心安装器" for t in tasks],
                "reason": "确认后执行；配置写入不等于故障已解决，随后自动复检。"}

    def apply(self, token, report, confirmed=False):
        if confirmed is not True:
            return {"state": "confirmation_required", "reason": "先审核具体影响并明确确认"}
        plan = self.plans.get(token) if isinstance(token, str) else None
        if not plan or time.monotonic() > plan["deadline"] or not self._current(report):
            return {"state": "retest_required", "reason": "方案已过期，请重新检测并生成方案。"}
        if report["report_id"] != plan["report_id"]:
            return {"state": "retest_required", "reason": "本机检测已变化，请重新生成方案，不执行旧方案。"}
        del self.plans[token]
        outputs, backups = [], []
        if plan["changes"]:
            value = self.config.apply(plan["changes"])
            outputs.append({"step": "config", "state": value["state"], "reason": value.get("reason", "配置已写入，尚待复检")})
            backups = value["backups"]
            if value["state"] != "completed":
                return {"state": value["state"], "steps": outputs, "backups": backups, "before": plan["before"], "needs_retest": True}
        for task in plan["tasks"]:
            if task == "config":
                continue
            value = self.legacy.run(task, {}, confirmed=True)
            outputs.append({"step": task, "state": value["state"], "reason": value.get("reason", "维护操作已返回，尚待复检")})
            if value["state"] not in ("completed", "started"):
                return {"state": "partial" if backups else "failed", "steps": outputs, "backups": backups, "before": plan["before"], "needs_retest": True,
                        "reason": "配置修改已完成，但维护步骤未完成；保留备份并复检实际状态。" if backups else "维护步骤未完成，尚未确认修复生效；现在复检实际状态。"}
        waiting = "install" in plan["tasks"]
        return {"state": "waiting_install" if waiting else "executed", "steps": outputs, "backups": backups,
                "before": plan["before"], "needs_retest": not waiting,
                "reason": "完成安装后点击继续复检。" if waiting else "修改已执行；请重开受影响的 Claude 客户端，现在复检配置与连接。"}
