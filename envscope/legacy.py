"""Explicit adapters for the original, separately installed Claude Switcher.

Catalog and planning calls only read files. Nothing is installed, repaired,
updated, or launched on import or during discovery. The bundled source is an
immutable installer/reference copy; upstream updaters only target the original
installation and are never used to update EnvScope.

An injected runner has the subprocess-like contract
``runner(argv, *, input=None, env=None, timeout=..., launch_mode="capture")``.
It returns a CompletedProcess-like object (or mapping) with returncode/stdout/
stderr. Tests use fake runners, never the user's installed maintenance scripts.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tempfile
import threading
from urllib.parse import unquote, urlsplit

from .report import redact


UPSTREAM_COMMIT = "870c4ca0754234965878ef58144d7a755d965037"
UPSTREAM_REPOSITORY = "https://github.com/YOURSJEYO/claude-switcher"
MANIFEST_NAME = "VENDOR_MANIFEST.json"
VENDOR_MANIFEST_SHA256 = "057f2c7c96c74ff82cc655ec82182ee9f48523b9b7096255256aaceac074781f"
OUTPUT_LIMIT = 65536
MAC_CLIENTS = ("clash-verge", "shadowrocket", "sing-box", "clashx", "surge", "auto")

# Only literal verbs can reach a subprocess. No API field can choose a core,
# interpreter, shell, script, execution policy, or command-line option.
COMMANDS = {
    "status": {"Darwin": "status", "Windows": "status"},
    "check": {"Darwin": "check"},
    "checkdetail": {"Darwin": "checkdetail", "Windows": "checkdetail"},
    "fix": {"Darwin": "fix", "Windows": "fix"},
    "update-check": {"Darwin": "update-check", "Windows": "check-update"},
    "update-apply": {"Darwin": "update", "Windows": "update-now"},
    "set-region": {"Darwin": "set-region"},
    "set-client": {"Darwin": "set-client"},
    "fingerprint": {"Darwin": "fingerprint"},
    "cli-info": {"Darwin": "cli-info"},
    "open-safe": {"Darwin": "open-safe"},
    "snapshot-export": {"Darwin": "snapshot-export"},
    "snapshot-import": {"Darwin": "snapshot-import"},
    "diagnose-proxy": {"Darwin": "diagnose-proxy"},
}
ALIASES = {"installer": "install", "update": "update-apply", "check-update": "update-check"}
PARAMETERS = {
    "fix": {"webrtc_policy"}, "set-client": {"client"}, "open-safe": {"url"},
    "snapshot-export": {"account", "file", "password"},
    "snapshot-import": {"account", "file", "password"}, "diagnose-proxy": {"proxy"},
}
EFFECTS = {
    "install": ["安装原版核心和界面", "可能修改时区、IPv6、代理配置并注册后台保护", "打开交互式安装器，需自行完成授权"],
    "uninstall": ["打开原版交互式卸载器", "移除原版核心、桌面界面和后台保护；原版保留账号存档"],
    "status": ["读取原版账号状态；原版入口可能创建 accounts 目录"],
    "check": ["运行原版检查并记录 IP 历史；不等于 EnvScope 独立验证"],
    "checkdetail": ["运行原版逐项检查并写入 IP 历史和 last-check.txt"],
    "fix": ["可能重启代理、改写规则、修改时区与 IPv6 并恢复后台保护", "macOS 还可能更改地区格式和 Claude 语言"],
    "update-check": ["检查原版更新；macOS 原版入口可能创建 accounts 目录", "仅报告原版更新，不更新 EnvScope"],
    "update-apply": ["下载、校验、备份并替换已安装的原版脚本", "可能重启原版后台保护；不更新 EnvScope"],
    "set-region": ["按当前出口重设国家目标、系统时区和地区格式，并同步原版看门狗"],
    "set-client": ["改写已安装原版核心的代理客户端配置"],
    "fingerprint": ["读取字体、显示与虚拟化信息；原版入口可能创建 accounts 目录"],
    "cli-info": ["读取 CLI 安装信息并调用版本检查；原版入口可能创建 accounts 目录"],
    "open-safe": ["启动独立临时浏览器配置，窗口退出后由原版清理"],
    "snapshot-export": ["读取非活动账号存档并创建 AES-256 加密 DMG；密码仅经标准输入传递"],
    "snapshot-import": ["只读挂载加密 DMG，并导入空账号槽位；密码仅经标准输入传递"],
    "diagnose-proxy": ["经明确指定的代理发出无认证传输请求；不验证账号、应用可用性或防泄漏"],
}


def _platform_name(value):
    return {"macOS": "Darwin", "macos": "Darwin", "darwin": "Darwin", "win32": "Windows",
            "windows": "Windows"}.get(value, value)


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8-sig", errors="replace")
    return value if isinstance(value, str) else ""


def _windows_interactive(argv):
    """Ask Windows for UAC with an argv-escaped command, never a shell string."""
    if os.name != "nt":
        raise OSError("Windows installation requires Windows")
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.lpVerb = "runas"
    info.lpFile = argv[0]
    info.lpParameters = subprocess.list2cmdline(argv[1:])
    info.lpDirectory = str(Path(argv[-1]).parent)
    # The original installer asks Read-Host/pause questions, so its window must
    # be visible after the user's explicit installation click.
    info.nShow = 1
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:
            return {"returncode": 1223, "stdout": "", "stderr": "Administrator authorization cancelled"}
        raise OSError(error, "Unable to open the original installer")
    return {"returncode": 0, "stdout": "", "stderr": ""}


def _default_runner(argv, *, input=None, env=None, timeout=180, launch_mode="capture"):
    if launch_mode == "windows_elevated_interactive":
        return _windows_interactive(argv)
    # Secure temporary files bound memory use even when a legacy command emits
    # excessive output. They disappear when the command finishes.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(argv, input=input.encode("utf-8") if input is not None else None,
                                env=env, stdout=output, stderr=errors, timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        output.seek(0)
        errors.seek(0)
        return {"returncode": result.returncode, "stdout": output.read(OUTPUT_LIMIT),
                "stderr": errors.read(OUTPUT_LIMIT)}


class LegacyBridge:
    def __init__(self, platform_name=None, home=None, vendor_root=None, runner=None):
        self.platform = _platform_name(platform_name or platform.system())
        self.home = Path(home) if home is not None else Path.home()
        self.vendor_root = Path(vendor_root) if vendor_root is not None else Path(__file__).parent / "vendor" / "claude_switcher"
        self.runner = runner or _default_runner
        self._lock = threading.Lock()

    @property
    def core(self):
        if self.platform == "Darwin":
            return self.home / ".local" / "bin" / "claude-switch.sh"
        return self.home / ".claude-switcher" / "claude-switch.ps1"

    def _vendor_integrity(self):
        result = {"verified": False, "commit": UPSTREAM_COMMIT, "reason": "vendor_manifest_unavailable"}
        try:
            manifest_path = self.vendor_root / MANIFEST_NAME
            if manifest_path.is_symlink() or manifest_path.stat().st_size > 1048576:
                return result
            manifest_bytes = manifest_path.read_bytes()
            if hashlib.sha256(manifest_bytes).hexdigest() != VENDOR_MANIFEST_SHA256:
                return {**result, "reason": "vendor_manifest_integrity_failed"}
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            files = manifest["files"]
            if (manifest.get("schema_version") != 1 or manifest.get("commit") != UPSTREAM_COMMIT
                    or manifest.get("repository") != UPSTREAM_REPOSITORY or manifest.get("license") != "MIT"
                    or not isinstance(files, dict) or not files or "LICENSE" not in files or "SHA256SUMS" not in files):
                return {**result, "reason": "vendor_manifest_invalid"}
            root = self.vendor_root.resolve()
            for relative, metadata in files.items():
                path = PurePosixPath(relative)
                if path.is_absolute() or ".." in path.parts or ".git" in path.parts or "\\" in relative:
                    return {**result, "reason": "vendor_manifest_invalid"}
                file = self.vendor_root.joinpath(*path.parts)
                if (file.is_symlink() or not file.resolve().is_relative_to(root) or not file.is_file()
                        or file.stat().st_size != metadata["size"]
                        or hashlib.sha256(file.read_bytes()).hexdigest() != metadata["sha256"]):
                    return {**result, "reason": "vendor_integrity_failed"}
            actual = {p.relative_to(self.vendor_root).as_posix() for p in self.vendor_root.rglob("*") if p.is_file()}
            if actual != set(files) | {MANIFEST_NAME}:
                return {**result, "reason": "unexpected_vendor_files"}
            return {"verified": True, "commit": UPSTREAM_COMMIT, "reason": "all_pinned_source_hashes_match", "file_count": len(files)}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return result

    def _backend_acceptable(self):
        try:
            resolved = self.core.resolve()
            return (not self.core.is_symlink()
                    and not resolved.is_relative_to(self.vendor_root.resolve())
                    and not resolved.is_relative_to(Path(__file__).resolve().parent))
        except OSError:
            return False

    def _installed_commands(self):
        try:
            if not self._backend_acceptable() or not self.core.is_file() or self.core.stat().st_size > 4194304:
                return set()
            text = self.core.read_text(encoding="utf-8-sig")
        except (OSError, ValueError):
            return set()
        if self.platform == "Windows":
            return set(re.findall(r"(?m)^\s*'([a-z-]+)'\s*\{", text))
        commands = set(re.findall(r"(?m)^\s*([a-z-]+)\)\s", text))
        if "PY_PROXY_DIAGNOSE" in text and '"diagnose-proxy"' in text:
            commands.add("diagnose-proxy")
        return commands

    def _descriptor(self, action, commands, vendor):
        native = COMMANDS.get(action, {}).get(self.platform)
        platform_supported = self.platform in ("Windows", "Darwin")
        source = None
        if action == "install" and platform_supported:
            source = "windows/install.ps1" if self.platform == "Windows" else "installer/安装.command"
        elif action == "uninstall" and self.platform == "Darwin":
            source = "installer/卸载.command"
        supported = bool(native or source)
        available = bool(vendor["verified"] if source else native and native in commands)
        if not supported:
            reason = "not_in_upstream_for_platform"
        elif source and not vendor["verified"]:
            reason = vendor["reason"]
        elif not source and not self.core.is_file():
            reason = "original_core_not_installed"
        elif not source and not self._backend_acceptable():
            reason = "installed_core_must_not_alias_envscope_or_a_symlink"
        elif not source and native not in commands:
            reason = "command_not_supported_by_installed_core"
        else:
            reason = "available"
        return {"id": action, "supported": supported, "available": available, "reason": reason,
                "requires_confirmation": not (action == "diagnose-proxy" or action == "update-check" and self.platform == "Windows"),
                "requires_preflight": action == "open-safe", "launches_claude": False,
                "launches_external_app": action in ("install", "uninstall", "fix", "open-safe"),
                "effects": EFFECTS[action], "native_command": native, "source": source,
                "updates_envscope": False}

    def capabilities(self):
        """Read the fixed paths and vendor hashes without creating account state."""
        vendor = self._vendor_integrity()
        commands = self._installed_commands() if self.platform in ("Windows", "Darwin") else set()
        actions = [self._descriptor(action, commands, vendor) for action in ("install", "uninstall", *COMMANDS)]
        actions.append({"id": "switch", "supported": False, "available": False,
                        "reason": "managed_by_envscope_accounts", "requires_confirmation": True,
                        "requires_preflight": True, "launches_claude": True, "effects": [], "updates_envscope": False})
        templates = (["windows/claude-bodyguard.ps1"] if self.platform == "Windows" else
                     ["daemons/claude-bodyguard.sh", "daemons/tz-watchdog.sh", "daemons/local.claude-bodyguard.plist",
                      "daemons/local.tz-watchdog.plist", "daemons/local.claude-update.plist"] if self.platform == "Darwin" else [])
        return {"platform": self.platform, "upstream": {"repository": UPSTREAM_REPOSITORY, "commit": UPSTREAM_COMMIT},
                "backend": {"installed": self.core.is_file() if self.platform in ("Windows", "Darwin") else False,
                            "path": str(self.core), "verified_by_envscope": False},
                "vendor": vendor, "actions": actions,
                "templates": [{"source": name, "available": vendor["verified"], "executable": False} for name in templates],
                "boundary": "Original commands are maintenance operations; reported ok never becomes an EnvScope privacy pass."}

    @staticmethod
    def _validate_url(value, proxy=False):
        if not isinstance(value, str) or not value or len(value) > 8192 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid_proxy" if proxy else "invalid_url")
        try:
            parsed = urlsplit(value)
            allowed = ("http", "https", "socks5", "socks5h") if proxy else ("http", "https")
            if parsed.scheme not in allowed or not parsed.hostname:
                raise ValueError("invalid URL")
            port = parsed.port
            if port is not None and not 0 < port <= 65535:
                raise ValueError("invalid port")
            if proxy and (port is None or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
                raise ValueError("invalid proxy")
            if not proxy and (parsed.username is not None or parsed.password is not None):
                raise ValueError("URL credentials are not allowed")
        except (ValueError, TypeError):
            raise ValueError("invalid_proxy" if proxy else "invalid_url") from None
        return value

    def _parameters(self, action, params):
        if params is None:
            params = {}
        if not isinstance(params, dict) or set(params) - PARAMETERS.get(action, set()):
            raise ValueError("unexpected_parameters")
        values = dict(params)
        if action == "set-client" and values.get("client") not in MAC_CLIENTS:
            raise ValueError("invalid_client")
        if action == "fix" and "webrtc_policy" in values:
            if self.platform != "Darwin" or values["webrtc_policy"] not in ("proxy", "reject"):
                raise ValueError("invalid_webrtc_policy")
        if action == "open-safe":
            self._validate_url(values.get("url"))
        if action == "diagnose-proxy":
            self._validate_url(values.get("proxy"), proxy=True)
        if action in ("snapshot-export", "snapshot-import"):
            if values.get("account") not in ("A", "B", "C", "D"):
                raise ValueError("invalid_account")
            file = values.get("file")
            if not isinstance(file, str) or not file or len(file) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in file):
                raise ValueError("invalid_file")
            path = Path(file)
            if not path.is_absolute():
                raise ValueError("absolute_file_required")
            accounts = self.home / ".claude-switcher" / "accounts"
            base = self.home / ".claude-switcher"
            if accounts.is_symlink() or base.is_symlink() or not accounts.resolve().is_relative_to(base.resolve()):
                raise ValueError("unsafe_account_path")
            account = accounts / values["account"]
            if account.is_symlink():
                raise ValueError("unsafe_account_path")
            if action == "snapshot-export":
                if path.exists() or path.is_symlink() or not path.parent.is_dir():
                    raise ValueError("export_target_must_be_new")
                if not account.is_dir():
                    raise ValueError("account_snapshot_missing")
                current = base / "current"
                if current.is_file():
                    if current.stat().st_size > 128:
                        raise ValueError("invalid_current_account")
                    if current.read_text(encoding="utf-8").strip() == values["account"]:
                        raise ValueError("cannot_export_active_account")
            else:
                if not path.is_file() or path.is_symlink():
                    raise ValueError("import_file_missing")
                if account.exists():
                    raise ValueError("account_slot_not_empty")
            if "password" in values:
                password = values["password"]
                if (not isinstance(password, str) or not password or len(password) > 4096
                        or any(c in password for c in ("\r", "\n", "\0"))
                        or action == "snapshot-export" and len(password) < 8):
                    raise ValueError("invalid_password")
            values["file"] = str(path)
        return values

    def _powershell(self):
        system = os.environ.get("SystemRoot", os.environ.get("WINDIR", r"C:\Windows"))
        return str(Path(system) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")

    def plan(self, action, params=None):
        """Return a reviewable literal argv plan, without running or writing it."""
        action = ALIASES.get(action, action) if isinstance(action, str) else ""
        if action == "switch":
            return {"action": action, "state": "rejected", "reason": "managed_by_envscope_accounts"}
        if action not in COMMANDS and action not in ("install", "uninstall"):
            return {"action": "unknown", "state": "rejected", "reason": "unknown_action"}
        try:
            values = self._parameters(action, params)
        except (ValueError, OSError) as error:
            reason = str(error) if isinstance(error, ValueError) else "local_resource_unavailable"
            return {"action": action, "state": "rejected", "reason": reason}
        catalog = self.capabilities()
        descriptor = next(item for item in catalog["actions"] if item["id"] == action)
        plan = {**descriptor, "action": action, "state": "planned", "product": "claude-switcher", "timeout": 180,
                "launch_mode": "capture", "verified_by_envscope": False}
        if not descriptor["supported"] or not descriptor["available"]:
            return {**plan, "state": "unsupported" if not descriptor["supported"] else "unavailable"}
        if action in ("install", "uninstall"):
            source = str(self.vendor_root / descriptor["source"])
            if self.platform == "Windows":
                plan["argv"] = [self._powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", source]
                plan["launch_mode"] = "windows_elevated_interactive"
            else:
                plan["argv"] = ["/usr/bin/open", "-a", "Terminal", source]
                plan["launch_mode"] = "macos_terminal_interactive"
            plan["timeout"] = 15
            return plan
        if self.platform == "Windows":
            argv = [self._powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(self.core)]
        else:
            argv = ["/bin/bash", str(self.core)]
        argv.append(descriptor["native_command"])
        if action == "set-client":
            argv.append(values["client"])
        elif action == "open-safe":
            argv.append(values["url"])
        elif action == "snapshot-export":
            argv.extend([values["account"], values["file"], "--password-stdin"])
        elif action == "snapshot-import":
            argv.extend([values["file"], values["account"], "--password-stdin"])
        plan["argv"] = argv
        plan["stdin_required"] = action in ("snapshot-export", "snapshot-import")
        plan["timeout"] = 600 if action in ("snapshot-export", "snapshot-import", "fix", "update-apply") else 120
        return plan

    def _environment(self, action, values):
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith("CLAUDE_SWITCHER_") and key.upper() != "WEBRTC_POLICY"}
        env["HOME"] = str(self.home)
        if self.platform == "Windows":
            env["USERPROFILE"] = str(self.home)
        if action == "diagnose-proxy":
            env["CLAUDE_SWITCHER_PROXY_URL"] = values["proxy"]
        if action == "fix" and "webrtc_policy" in values:
            env["WEBRTC_POLICY"] = values["webrtc_policy"]
        if action == "set-client":
            env["CLAUDE_SWITCHER_CORE"] = str(self.core)
        return env

    def _clean_output(self, stdout, stderr, values):
        secrets = [str(self.home)]
        for key in ("password", "proxy", "file"):
            value = values.get(key)
            if isinstance(value, str) and value:
                secrets.append(value)
        if "proxy" in values:
            proxy = urlsplit(values["proxy"])
            secrets.extend(unquote(value) for value in (proxy.username, proxy.password) if value)
        cleaned = {}
        for key, value in (("stdout", stdout), ("stderr", stderr)):
            value = _text(value)[:OUTPUT_LIMIT]
            for secret in sorted(set(secrets), key=len, reverse=True):
                value = value.replace(secret, "[redacted]")
            value = re.sub(r"(?i)(?:https?|socks5h?)://[^\s<>\"']+", "[url]", value)
            value = re.sub(r"(?i)\b(password|passwd|token|secret|authorization|cookie)(\s*[:=]\s*)[^\s,;]+", r"\1\2[redacted]", value)
            cleaned[key] = value
        result = redact(cleaned)
        return result["stdout"], result["stderr"]

    @staticmethod
    def _signature(path):
        try:
            stat = path.stat()
            return stat.st_mtime_ns, stat.st_size
        except OSError:
            return None

    def run(self, action, params=None, confirmed=False, preflight=None):
        """Execute only an available allowlisted plan after its explicit gates.

        The fresh preflight is a callable invoked immediately before open-safe;
        it must return exactly True. A previously saved report/boolean cannot be
        supplied as an authorization. Legacy account switch is always rejected.
        """
        plan = self.plan(action, params)
        result = {"action": plan["action"], "state": plan["state"], "code": None, "stdout": "", "stderr": "",
                  "reason": plan.get("reason", ""), "verified_by_envscope": False, "updates_envscope": False}
        if plan["state"] != "planned":
            return result
        if plan["requires_confirmation"] and confirmed is not True:
            return {**result, "state": "blocked", "reason": "explicit_confirmation_required"}
        try:
            values = self._parameters(plan["action"], params)
        except (ValueError, OSError):
            return {**result, "state": "blocked", "reason": "parameters_or_local_resources_changed"}
        if plan.get("stdin_required") and "password" not in values:
            return {**result, "state": "blocked", "reason": "password_required_via_private_stdin"}
        if not self._lock.acquire(blocking=False):
            return {**result, "state": "blocked", "reason": "legacy_operation_running"}
        try:
            if plan["requires_preflight"]:
                try:
                    passed = callable(preflight) and preflight() is True
                except Exception:
                    passed = False
                if not passed:
                    return {**result, "state": "blocked", "reason": "fresh_preflight_required"}
            output_file = (self.home / ".claude-switcher" / ("last-check.txt" if plan["action"] == "checkdetail" else "last-fix.txt"))
            previous_output = self._signature(output_file) if self.platform == "Windows" and plan["action"] in ("checkdetail", "fix") else None
            response = self.runner(plan["argv"], input=values["password"] + "\n" if plan.get("stdin_required") else None,
                                   env=self._environment(plan["action"], values), timeout=plan["timeout"], launch_mode=plan["launch_mode"])
            get = response.get if isinstance(response, dict) else lambda name, default=None: getattr(response, name, default)
            code = get("returncode", get("code"))
            stdout, stderr = _text(get("stdout", "")), _text(get("stderr", ""))
            if self.platform == "Windows" and plan["action"] in ("checkdetail", "fix"):
                # PowerShell 5.1 stdout can be GBK/936. Only a newly written UTF-8
                # result is eligible, never an old last-check/last-fix report.
                signature = self._signature(output_file)
                if signature is not None and signature != previous_output and output_file.stat().st_size <= OUTPUT_LIMIT:
                    stdout = output_file.read_text(encoding="utf-8-sig")
            public_out, public_error = self._clean_output(stdout, stderr, values)
            result.update(code=code if type(code) is int else None, stdout=public_out, stderr=public_error)
            if code == 1223:
                return {**result, "state": "cancelled", "reason": "administrator_authorization_cancelled"}
            if type(code) is not int or code != 0:
                return {**result, "state": "failed", "reason": "original_command_failed"}
            if plan["launch_mode"] != "capture":
                return {**result, "state": "started", "reason": "interactive_operation_opened_completion_not_observed"}
            if not stdout.strip():
                return {**result, "state": "failed", "reason": "original_command_returned_no_result"}
            if re.search(r"(?m)^FAIL:|^STATUS=error\s*$|^[^\r\n=]{1,80}=fail(?::|$)|✗", stdout):
                return {**result, "state": "failed", "reason": "original_command_reported_failure"}
            return {**result, "state": "completed", "reason": "original_command_finished_not_independently_verified"}
        except subprocess.TimeoutExpired:
            return {**result, "state": "unknown", "reason": "deadline_reached_effects_require_review"}
        except (OSError, ValueError, TypeError):
            # Native errors and tracebacks may contain private filenames/secrets.
            return {**result, "state": "failed", "reason": "original_command_unavailable_or_invalid_result"}
        finally:
            self._lock.release()
