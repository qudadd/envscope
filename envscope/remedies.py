"""Reviewed, fixed-target configuration edits with private backups and undo.

No shell strings, arbitrary paths, credential installation, automatic system
network edits or repairs inferred from an untrusted imported report.
"""
from datetime import datetime, timezone
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time

from .config_files import inspect_text, load_object, remove_trailing_commas
from .discovery import safe_local_proxy

MAX_CONFIG = 1048576
LABELS = {"desktop": "Claude 桌面配置", "cli": "Claude Code 用户配置"}
GUARDED_KEYS = ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "NODE_TLS_REJECT_UNAUTHORIZED")


def validate_guard(values):
    if not isinstance(values, dict) or set(values) != set(GUARDED_KEYS):
        raise ValueError("维护基线只能包含已列出的 Code 环境设置")
    for key, value in values.items():
        if value is not None and (not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 for c in value)):
            raise ValueError("维护基线值无效")
        if key in ("HTTPS_PROXY", "https_proxy") and value is not None:
            if not safe_local_proxy(value) or not value.startswith(("http://", "https://")):
                raise ValueError("自动保持只支持不含凭据的本机 HTTP / HTTPS 代理")
        if key in ("NO_PROXY", "no_proxy") and value is not None and _without_targets(value) != ",".join(p for p in re.split(r"[,;\s]+", value) if p):
            raise ValueError("先修正匹配 Claude 的 NO_PROXY 条目，再建立维护基线")
        if key == "NODE_TLS_REJECT_UNAUTHORIZED" and value not in (None, "1"):
            raise ValueError("不能长期保持关闭证书校验的配置")
    proxies = {values[k] for k in ("HTTPS_PROXY", "https_proxy") if values[k] is not None}
    if len(proxies) > 1 or not proxies and values["NODE_TLS_REJECT_UNAUTHORIZED"] != "1":
        raise ValueError("请先配置一致的本机 HTTPS 代理或显式开启 TLS 校验，再建立维护基线")
    return dict(values)


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
        if target not in self.paths or set(kinds) - {"trailing_comma", "proxy", "tls", "direct"}:
            raise ValueError("未知配置修复")
        if 'direct' in kinds and 'proxy' in kinds:
            raise ValueError('连接方式不能同时设置为代理与系统路由')
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
        if set(kinds) & {"proxy", "tls", "direct"}:
            data = json.loads(text)
            before_values = deepcopy(data)
            env = data.setdefault("env", {}) if set(kinds) & {'proxy', 'tls'} else data.get('env', {})
            if 'direct' in kinds:
                for key in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy'):
                    env.pop(key, None)
                effects.append('移除 Code 用户配置中的 HTTP(S)_PROXY / ALL_PROXY 大小写字段，以使用系统路由；终端及系统变量不变')
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
            if data == before_values and "trailing_comma" not in kinds:
                return None
            text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        after = (b"\xef\xbb\xbf" if original and original.startswith(b"\xef\xbb\xbf") else b"") + text.encode("utf-8")
        if len(after) > MAX_CONFIG:
            raise ValueError("修改后的配置超过大小上限，未执行写入")
        if original == after:
            return None
        fields = (["JSON 格式"] if "trailing_comma" in kinds else []) + (["HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"] if "proxy" in kinds else []) + (["NODE_TLS_REJECT_UNAUTHORIZED"] if "tls" in kinds else [])
        if 'direct' in kinds:
            fields += ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy']
        return {"target": target, "label": LABELS[target], "before": original, "after": after, "fields": fields,
                "before_hash": digest(original) if original is not None else None, "after_hash": digest(after), "effects": effects}

    def connection_context(self, repair_json=False):
        """Inspect the current fixed Code file without returning credentials."""
        original = _read(self.paths["cli"])
        text = original.decode("utf-8-sig") if original is not None else "{}"
        if repair_json:
            text = remove_trailing_commas(text) or text
        if inspect_text(text).get("valid") is not True:
            raise ValueError("请先修正 Code 配置格式，再完善连接设置")
        env = {**self.environ, **load_object(text).get("env", {})}
        value = next((env.get(k) for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY") if env.get(k)), "")
        inherited_keys = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY",
                          "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "NODE_EXTRA_CA_CERTS")
        return {"custom_provider": bool(env.get("ANTHROPIC_BASE_URL")) or any(env.get(k) == "1" for k in
                    ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")),
                "proxy_configured": bool(value), "local_proxy": safe_local_proxy(value) if value else None,
                "inherited_proxy_configured": any(self.environ.get(k) for k in ('https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY')),
                "environment_hash": digest(json.dumps({k: self.environ.get(k) for k in inherited_keys}, sort_keys=True).encode())}

    def verify_receipts(self, receipts):
        """Read after the audit; publish scoped confirmation, never file hashes."""
        result = []
        for receipt in receipts:
            target = receipt.get("target")
            if target not in self.paths:
                raise ValueError("未知配置核对目标")
            try:
                current = _read(self.paths[target])
                state = "verified" if current is not None and digest(current) == receipt["after_hash"] else "changed"
            except (ValueError, OSError):
                state = "unverified"
            result.append({"target": target, "label": LABELS[target], "state": state,
                           "fields": receipt.get("fields", []), "scope": "user-config-file-only"})
        return result

    def apply(self, changes):
        with self._lock():
            return self._apply(changes)

    def capture_guard(self):
        original = _read(self.paths["cli"])
        if original is None:
            raise ValueError("请先完成 Code 配置，再启用配置自动保持")
        text = original.decode("utf-8-sig")
        if inspect_text(text).get("valid") is not True:
            raise ValueError("请先修正 Code 配置格式，再建立维护基线")
        data = load_object(text)
        if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
            raise ValueError("Code 配置结构无法识别")
        values = validate_guard({key: data.get("env", {}).get(key) for key in GUARDED_KEYS})
        return values, digest(original)

    def preview_guard(self, values):
        """Restore only approved env keys, preserving all unrelated current values."""
        values = validate_guard(values)
        original = _read(self.paths["cli"])
        if original is None:
            raise ValueError("Code 配置已删除；不会在后台重新创建，需人工复核")
        data = load_object(original.decode("utf-8-sig"))
        if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
            raise ValueError("Code 配置格式有误；不会用基线覆盖整份文件")
        env = data.setdefault("env", {})
        changed = [key for key, value in values.items() if env.get(key) != value or value is None and key in env]
        if not changed:
            return None
        for key in changed:
            if values[key] is None:
                env.pop(key, None)
            else:
                env[key] = values[key]
        after = (b"\xef\xbb\xbf" if original.startswith(b"\xef\xbb\xbf") else b"") + (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if len(after) > MAX_CONFIG:
            raise ValueError("配置过大，未恢复维护基线")
        return {"target": "cli", "label": LABELS["cli"], "before": original, "after": after,
                "before_hash": digest(original), "after_hash": digest(after),
                "effects": ["恢复已批准的 Code 字段：" + ", ".join(changed)], "keys": changed}

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

    def backup_status(self, token):
        try:
            if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24}", token):
                return "unavailable"
            metadata = _read(self.backups / (token + ".recovery.json"))
            meta = load_object(metadata.decode("utf-8")) if metadata else {}
            if meta.get("undone_at"):
                return "undone"
            if meta.get("target") not in self.paths or not isinstance(meta.get("after_hash"), str):
                return "unavailable"
            current = _read(self.paths[meta["target"]])
            return "available" if current is not None and digest(current) == meta["after_hash"] else "changed"
        except (OSError, ValueError, UnicodeError, AttributeError):
            return "unavailable"

    def list_backups(self):
        """Expose recovery metadata only; never expose original config contents."""
        try:
            root = _safe(self.backups)
            files = sorted(root.glob("*.recovery.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:100]
        except (OSError, ValueError):
            return []
        records = []
        for file in files:
            token = file.name.removesuffix(".recovery.json")
            if not re.fullmatch(r"[A-Za-z0-9_-]{24}", token):
                continue
            try:
                body = _read(file)
                metadata = load_object(body.decode("utf-8")) if body else {}
                if metadata.get("target") not in LABELS or not isinstance(metadata.get("after_hash"), str):
                    continue
                records.append({"id": token, "label": LABELS[metadata["target"]],
                                "created_at": metadata.get("created_at"), "availability": self.backup_status(token)})
            except (OSError, ValueError, UnicodeError, AttributeError):
                continue
            if len(records) >= 20:
                break
        return records

    def _undo(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24}", token):
            raise ValueError("备份编号无效")
        if self.backup_status(token) != "available":
            raise ValueError("备份记录已撤销、无法核实或当前文件又被修改，未执行恢复")
        if token not in self.undo_records:
            metadata = _read(self.backups / (token + ".recovery.json"))
            if metadata is None:
                raise ValueError("恢复记录不存在")
            meta = load_object(metadata.decode("utf-8"))
            if (not isinstance(meta, dict) or meta.get("target") not in self.paths or meta.get("undone_at")
                    or type(meta.get("original_existed")) is not bool or not re.fullmatch(r"[0-9a-f]{64}", str(meta.get("after_hash", "")))):
                raise ValueError("恢复记录无效或已撤销")
            before = _read(self.backups / (token + ".private.json")) if meta["original_existed"] else None
            after = _read(self.paths[meta["target"]])
            if (meta["original_existed"] and (before is None or digest(before) != meta.get("before_hash"))
                    or after is None or digest(after) != meta["after_hash"]):
                raise ValueError("备份或当前配置已变化，未执行恢复")
            self.undo_records[token] = {"target": meta["target"], "label": LABELS[meta["target"]],
                                        "before": before, "after": after, "backup": self.backups / (token + ".private.json")}
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
        recovery = self.backups / (token + ".recovery.json")
        metadata = _read(recovery)
        if metadata is not None:
            meta = load_object(metadata.decode("utf-8"))
            meta["undone_at"] = datetime.now(timezone.utc).isoformat()
            _replace(recovery, json.dumps(meta).encode("utf-8"), metadata)
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

    @staticmethod
    def _proxy_verified(result):
        if not isinstance(result, dict) or not isinstance(result.get("evidence"), list):
            return False
        return any(isinstance(e, dict) and e.get("endpoint") == "https://api.anthropic.com/v1/models"
                   and type(e.get("http_status")) is int and e["http_status"] in (200, 401)
                   and e.get("tls_verified") is True and not e.get("error") for e in result["evidence"])

    def prepare(self, report, check_id=None, enhance_cli=False, proxy=None):
        if type(enhance_cli) is not bool:
            raise ValueError("完善 Code 配置需要明确的布尔选项")
        if proxy is not None and (not isinstance(proxy, str) or not safe_local_proxy(proxy) or not proxy.startswith(("http://", "https://"))):
            raise ValueError("仅可选用不含凭据的本机 HTTP / HTTPS 代理")
        if check_id is not None and (enhance_cli or proxy is not None):
            raise ValueError("逐项处理不能混用额外配置选项")
        if proxy is not None and not enhance_cli:
            raise ValueError("先选择完善 Code 连接设置，再指定代理")
        if not self._current(report):
            return {"state": "retest_required", "reason": "请先完成一次新的本机一键检测，再生成处理方案。"}
        problems = report["diagnosis"]["problems"]
        if check_id is not None:
            from .claude_checks import CHECK_PROBLEMS
            if check_id not in CHECK_PROBLEMS:
                raise ValueError("未知逐项检查")
            problems = [p for p in problems if any(p["id"].startswith(prefix) for prefix in CHECK_PROBLEMS[check_id])]
        tasks, effects, manual, kinds, connections = [], [], [], {}, []
        cli_finding = next((f for f in report.get("findings", []) if f["id"] == "extra.cli_env"), {})
        cli = next((v for v in cli_finding.get("evidence", []) if isinstance(v, dict)), {})
        cli_used = report.get("usage") in ("cli", "both") or report.get("usage") == "auto" and bool(cli.get("installation_count") or cli.get("config", {}).get("exists"))
        enhance_cli = enhance_cli and cli_used
        target = report.get('environment', {}).get('targets', {})
        system_route = bool(target) and target.get('connection_mode') in ('direct', 'tun')
        if system_route and proxy is not None:
            raise ValueError('当前目标通过系统路由连接，请先调整目标再选择 HTTP 代理')
        if target.get('target_proxy') and enhance_cli:
            if proxy is not None and proxy != target['target_proxy']:
                raise ValueError('所选代理与已确认目标不同，请先调整目标')
            proxy = target['target_proxy']
        elif target.get('connection_mode') == 'http_proxy' and enhance_cli and proxy is None:
            route = next((f for f in report.get('findings', []) if f['id'] == 'http.egress'), {})
            proxy = next((safe_local_proxy(r.get('proxy_endpoint')) for r in route.get('evidence', []) if safe_local_proxy(r.get('proxy_endpoint'))), None)
        for problem in problems:
            repair = problem.get("repair")
            if repair in ("json-desktop", "json-cli"):
                kinds.setdefault(repair.split("-")[1], set()).add("trailing_comma")
            elif repair == "cli-tls":
                kinds.setdefault("cli", set()).add("tls")
            elif repair == 'cli-direct' and system_route:
                kinds.setdefault('cli', set()).add('direct')
        if enhance_cli:
            kinds.setdefault("cli", set()).add("tls")
        proxy_needed = any(p.get("repair") == "cli-proxy" for p in problems)
        context = {}
        if proxy_needed or enhance_cli or 'direct' in kinds.get('cli', set()):
            try:
                context = self.config.connection_context("trailing_comma" in kinds.get("cli", set()))
            except (ValueError, OSError, UnicodeError):
                manual.append("Code 配置无法安全读取；本次不设置新的连接，先按具体行列位置修正。")
            if context.get("custom_provider"):
                manual.append("当前使用自定义接口或云平台。本次不替换其代理路径；请按服务提供方核对连接。证书校验可单独恢复。")
            elif context.get("proxy_configured") and not context.get("local_proxy") and not proxy_needed and proxy is None:
                manual.append("当前 Code 使用的代理不是可自动接管的本机地址。本次保留其连接；需要更换时请明确选择本机 HTTP 代理。")
        if system_route:
            if cli_used and context and (proxy_needed or enhance_cli or 'direct' in kinds.get('cli', set())):
                kinds.setdefault('cli', set()).add('direct')
                if context.get('inherited_proxy_configured'):
                    manual.append('当前终端仍继承 HTTP 代理，需在设置它的位置移除并重开 Code；不会改写系统或终端的环境变量。')
        can_choose_proxy = not system_route and bool(context) and not context.get("custom_provider") and (proxy_needed or enhance_cli and (proxy is not None or not context.get("proxy_configured") or bool(context.get("local_proxy"))))
        if can_choose_proxy:
            candidates = [proxy] if proxy else ([context["local_proxy"]] if context.get("local_proxy", "") and context["local_proxy"].startswith(("http://", "https://")) else [])
            if not proxy:
                candidates += [p["url"] for p in self.discoverer() if safe_local_proxy(p.get("url")) and p["url"].startswith(("http://", "https://"))]
            chosen = None
            for candidate in list(dict.fromkeys(candidates))[:3]:
                result = self.proxy_tester(candidate)
                verified = self._proxy_verified(result)
                connections.append({"proxy": candidate, "verified": verified,
                                    "evidence": result.get("evidence", []) if isinstance(result, dict) else []})
                if verified:
                    chosen = candidate
                    break
            if chosen:
                kinds.setdefault("cli", set()).add("proxy")
            else:
                manual.append("本次代理未取得 API 的有效连接证据，暂不改写 Code 代理。查看下面的 HTTP 状态与错误：连接被拒绝时检查端口；403 检查服务访问限制；超时检查线路。不要仅因网页拒绝自动探测而更改端口。")
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
        selected = next((row for row in report.get("claude_checks", {}).get("items", []) if row["id"] == check_id), None)
        needs_backend = (selected and selected["id"] in ("proxy", "tun", "guard", "rules")
                         and selected["status"] in ("warn", "fail", "unknown") and report.get("usage") != "cli"
                         and not (selected["id"] == "proxy" and kinds.get("cli")))
        if any(p.get("repair") == "legacy" for p in problems) or needs_backend:
            caps = self.legacy.capabilities()
            fix = next((a for a in caps["actions"] if a["id"] == "fix"), {})
            install = next((a for a in caps["actions"] if a["id"] == "install"), {})
            if fix.get("available"):
                tasks.append("fix")
                effects.extend(fix["effects"])
                if selected:
                    effects.insert(0, "为处理“" + selected["title"] + "”调用原版统一修复；该核心可能同时修改下列其他设置，请逐条审核")
            elif install.get("available"):
                tasks.append("install")
                effects.extend(install["effects"])
                manual.append("安装器是交互流程，完成后点击继续复检，以实际安装与运行状态为准。")
            else:
                manual.append("当前平台或已安装维护核心不支持自动修复，按问题列出的步骤处理后复检。")
        manual_items = [{"id": p["id"], "title": p["title"]} for p in problems if not p.get("repair")]
        if not tasks:
            return {"state": "guided", "effects": [], "manual": manual, "manual_items": manual_items, "connections": connections,
                    "reason": "本次仅提供处理步骤，没有可安全执行的写入。" if manual or manual_items else "本次无需写入配置；仍需在自己的 Claude 中确认实际使用。"}
        token = secrets.token_urlsafe(20)
        before = {"problems": [{"id": p["id"], "title": p["title"]} for p in problems]}
        if selected:
            before["check"] = {"id": selected["id"], "title": selected["title"], "status": selected["status"]}
        before["configuration"] = [{"target": c["target"], "after_hash": c["after_hash"], "fields": c.get("fields", [])} for c in changes]
        before["configuration_pending"] = list(manual)
        self.plans = {token: {"deadline": time.monotonic() + 90, "report_id": report["report_id"], "changes": changes,
                              "tasks": tasks, "problems": [p["id"] for p in problems],
                              "before": before, "proxy": chosen if changes and any("HTTPS_PROXY" in c.get("fields", []) for c in changes) else None,
                              "context": context, "repair_json": "trailing_comma" in kinds.get("cli", set())}}
        return {"state": "planned", "plan_id": token, "effects": effects, "manual": manual,
                "manual_items": manual_items, "connections": connections,
                "configuration_count": len(changes), "enhance_cli": enhance_cli,
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
        if plan.get('context') and self.config.connection_context(plan['repair_json']) != plan['context']:
            return {'state': 'retest_required', 'reason': 'Code 的连接来源在预览后发生变化，尚未写入，请重新检测。'}
        if plan.get("proxy"):
            if not self._proxy_verified(self.proxy_tester(plan["proxy"])):
                return {"state": "blocked", "backups": [], "before": plan["before"], "needs_retest": True,
                        "reason": "确认前的代理连接现已无法验证，本次没有写入配置。重新检测后再生成方案，不回退直连。"}
            if time.monotonic() > plan["deadline"] or not self._current(report):
                return {"state": "retest_required", "reason": "重新验证期间方案已过期，尚未写入，请重新检测。"}
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
