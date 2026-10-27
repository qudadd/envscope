"""User-triggered desktop operations; no maintenance action runs on import."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

from .accounts import AccountManager, AccountError
from .discovery import discover_proxies
from .legacy import LegacyBridge
from .report import redact
from .transport import CurlTransport, application_state
from .remedies import ConfigRemedies, SolutionPlans


def _process(command, timeout=8):
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def stop_claude():
    if platform.system() == "Windows":
        # Refuse an unrecognized same-name binary, rather than killing a CLI.
        code = r"""$p=@(Get-Process -Name Claude -ErrorAction SilentlyContinue)
foreach($item in $p){if(-not $item.Path -or $item.Path -notmatch '\\(?:WindowsApps\\[^\\]*Claude[^\\]*|Programs\\Claude|Claude|app-[^\\]+)\\'){exit 2}}
$p|Stop-Process -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if(Get-Process -Name Claude -ErrorAction SilentlyContinue){exit 1}
"""
        return _process(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code]).returncode == 0
    if platform.system() == "Darwin":
        _process(["/usr/bin/osascript", "-e", 'tell application "Claude" to quit'], timeout=8)
        return _process(["/usr/bin/pgrep", "-x", "Claude"]).returncode != 0
    return False


def launch_claude():
    if platform.system() == "Windows":
        code = "$a=Get-StartApps|Where-Object {$_.Name -eq 'Claude'}|Select-Object -First 1; if(-not $a){exit 1}; Start-Process explorer.exe -ArgumentList ('shell:AppsFolder\'+$a.AppID)"
        return _process(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code]).returncode == 0
    if platform.system() == "Darwin":
        return _process(["/usr/bin/open", "-a", "Claude"]).returncode == 0
    return False


def launch_gate(report, preferences):
    if not report:
        return False, ["请先完成一键检测"]
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(report["created_at"])).total_seconds()
        if not 0 <= age < 90:
            return False, ["检测已过期，请重新检测"]
    except (ValueError, TypeError, KeyError):
        return False, ["检测时间不可验证"]
    by_id = {f["id"]: f for f in report["findings"]}
    failed = [f["title"] for f in report["findings"] if f["status"] == "fail"]
    required = ["http.egress", "udp.stun", "baseline.proxy", "baseline.tun", "baseline.ipv6"]
    if preferences.get("require_guard", True):
        required.append("baseline.guard")
    if preferences.get("require_rules", True):
        required.append("baseline.rules")
    unverified = [by_id[k]["title"] if k in by_id else k for k in required if k not in by_id or by_id[k]["status"] != "pass"]
    reasons = ["存在失败项：" + ", ".join(failed)] if failed else []
    if unverified:
        reasons.append("启动前尚未通过：" + ", ".join(unverified))
    return not reasons, reasons


class Operations:
    def __init__(self, store, home=None, legacy=None, account_manager=None, discoverer=None, launcher=None, remedy_opener=None):
        self.store = store
        self.home = Path(home) if home else Path.home()
        self.legacy = legacy or LegacyBridge(home=self.home)
        self.discoverer = discoverer or discover_proxies
        self.launcher = launcher or launch_claude
        state = self.home / ".claude-switcher"
        data = (Path(os.environ.get("APPDATA", str(self.home / "AppData/Roaming"))) / "Claude"
                if platform.system() == "Windows" and home is None else self.home / "AppData/Roaming/Claude"
                if platform.system() == "Windows" else self.home / "Library/Application Support/Claude")
        self.accounts = account_manager or AccountManager(state, data, stop_app=stop_claude, launch_app=launch_claude)
        self.remedy_opener = remedy_opener or self._open_remedy
        self.config_remedies = ConfigRemedies(self.home, self.accounts.data_dir)
        self.solutions = SolutionPlans(self.config_remedies, self.legacy, self.discoverer,
                                      lambda proxy: self.run("proxy-diagnose", {"proxy": proxy}))

    def _open_remedy(self, action):
        system = platform.system()
        if action.startswith("config-"):
            path = self.config_remedies.backup_for_editor(action.removeprefix("config-"))
        elif action == "hosts-file":
            path = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/drivers/etc/hosts" if system == "Windows" else Path("/private/etc/hosts")
        else:
            path = None
        if system == "Windows":
            if path:
                command = [str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/notepad.exe"), str(path)]
            else:
                uri = {"clock-settings": "ms-settings:dateandtime", "storage-settings": "ms-settings:storagesense",
                       "proxy-settings": "ms-settings:network-proxy"}.get(action)
                if not uri:
                    return False
                command = [str(Path(os.environ.get("WINDIR", "C:/Windows")) / "explorer.exe"), uri]
        elif system == "Darwin":
            command = ["/usr/bin/open", "-e", str(path)] if path else ["/usr/bin/open", "-b", "com.apple.systempreferences"]
        else:
            return False
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True

    def catalog(self):
        try:
            accounts = self.accounts.list_accounts()
        except AccountError as error:
            accounts = {"current": None, "accounts": [], "pending": [], "error": str(error)}
        legacy = self.legacy.capabilities()
        for entry in legacy["actions"]:
            if entry["id"] in ("cli-info", "fingerprint") and platform.system() == "Windows":
                entry.update(supported=True, available=True, requires_confirmation=False, reason="native_read_only")
        return {"legacy": legacy, "accounts": accounts, "proxies": self.discoverer(),
                "settings": self.store.settings(), "history": self.store.history(),
                "added_features": ["事务式账号切换", "切换前重检", "历史对比", "出口变化提示", "代理自动发现", "代理连接诊断", "脱敏诊断包", "设置恢复"]}

    def run(self, action, params, confirmed=False, report=None, preflight=None):
        if not isinstance(params, dict):
            raise ValueError("invalid action parameters")
        native_parameters = {"account-label": {"slot", "label"}, "account-switch": {"slot"},
                             "account-export": {"slot", "file"}, "account-import": {"slot", "file"}, "app-launch": set(),
                             "proxy-diagnose": {"proxy"}, "support-bundle": set(), "history-compare": {"before", "after"},
                             "history-report": {"id"}, "settings-restore": set()}
        native_parameters.update({"solution-plan": {"report_id"}, "solution-apply": {"plan_id"}, "solution-undo": {"backup_id"}, "solution-open": {"problem_id", "report_id"}})
        if action in native_parameters and set(params) - native_parameters[action]:
            raise ValueError("unexpected action parameters")
        gate = preflight or (lambda: launch_gate(report, self.store.settings())[0])
        if action in ("solution-plan", "solution-open") and (not report or params.get("report_id") != report.get("report_id")):
            return {"state": "retest_required", "reason": "当前显示的不是本机最新检测，请重新检测后处理，不使用历史报告执行修复。"}
        if action == "solution-plan":
            return self.solutions.prepare(report)
        if action == "solution-apply":
            return self.solutions.apply(params.get("plan_id"), report, confirmed)
        if action == "solution-undo":
            return self.config_remedies.undo(params.get("backup_id"), confirmed)
        if action == "solution-open":
            problem = next((p for p in (report or {}).get("diagnosis", {}).get("problems", []) if p["id"] == params.get("problem_id")), None)
            if not problem:
                return {"state": "retest_required", "reason": "请重新检测，再使用当前问题的处理入口。"}
            target = problem["action"]
            if target not in ("config-desktop", "config-cli", "hosts-file", "clock-settings", "storage-settings", "proxy-settings"):
                raise ValueError("该问题没有可打开的本机入口")
            if target.startswith("config-") and confirmed is not True:
                return {"state": "confirmation_required", "reason": "将备份原配置，再用系统编辑器打开；备份可能含认证信息，仅保存在本机。"}
            opened = self.remedy_opener(target)
            return {"state": "opened" if opened else "unsupported", "reason": ("原配置已备份到 ~/.envscope/config-backups；已提交编辑器打开请求，编辑保存后重新检测。" if target.startswith("config-") else "已提交打开请求；完成上方步骤后点击重新检测。") if opened else "请按上方路径在系统设置中打开对应项目。"}
        if action == "account-label":
            return {"state": "completed", "account": self.accounts.rename_label(params.get("slot"), params.get("label"))}
        if action in ("account-switch", "account-export", "account-import", "app-launch"):
            if confirmed is not True:
                return {"state": "confirmation_required", "reason": "此操作会影响应用进程或账号文件"}
            if action == "account-switch":
                return {"state": "completed", "result": self.accounts.switch(params.get("slot"), preflight=gate)}
            if action == "account-export":
                return {"state": "completed", "result": self.accounts.copy_snapshot_to(params.get("slot"), params.get("file")),
                        "note": "这是未加密的本地目录备份，不能直接公开分享。加密镜像请使用 macOS 快照功能。"}
            if action == "account-import":
                return {"state": "completed", "result": self.accounts.import_snapshot_from(params.get("file"), params.get("slot"))}
            if gate() is not True:
                return {"state": "blocked", "reason": "启动前重新检测未通过，请返回检测页查看原因。"}
            launched = self.launcher()
            return {"state": "started" if launched else "failed", "reason": "已提交应用启动请求" if launched else "未找到可启动的 Claude 桌面应用"}
        if action == "proxy-diagnose":
            transport = CurlTransport(params.get("proxy"))
            if not transport.proxy:
                raise ValueError("explicit proxy required")
            evidence = []
            for url in ("https://claude.ai/", "https://api.anthropic.com/v1/models"):
                started = time.monotonic()
                response = transport.get(url, headers_only=True)
                evidence.append({"endpoint": url, "http_status": response.status, "access": application_state(response),
                                 "elapsed_ms": round((time.monotonic() - started) * 1000), "error": response.error,
                                 "timings": response.timings, "tls_verified": response.tls_verified})
            return {"state": "completed", "evidence": evidence, "boundary": "只验证明确指定代理的无认证连接；不证明账号可用。"}
        if action == "cli-info" and platform.system() == "Windows":
            if params:
                raise ValueError("unexpected parameters")
            candidates = {name: shutil.which(name) for name in ("claude", "claude.exe", "claude.cmd", "node", "npm")}
            return {"state": "completed", "installations": candidates, "config_exists": (self.home / ".claude").is_dir(),
                    "note": "只读安装位置，不自动卸载或升级。"}
        if action == "fingerprint" and platform.system() == "Windows":
            if params:
                raise ValueError("unexpected parameters")
            code = "@{gpu=@(Get-CimInstance Win32_VideoController|Select-Object Name,DriverVersion);machine=Get-CimInstance Win32_ComputerSystem|Select-Object Manufacturer,Model;fonts=@(Get-ChildItem $env:WINDIR\\Fonts -File|Select-Object -ExpandProperty Name)}|ConvertTo-Json -Depth 5 -Compress"
            result = _process(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code])
            return {"state": "completed" if result.returncode == 0 else "failed", "observations": json.loads(result.stdout) if result.returncode == 0 else {},
                    "note": "设备信息仅展示，不构成账号风险或地区判断。"}
        if action == "support-bundle":
            return {"state": "completed", "bundle": redact({"settings": {k: v for k, v in self.store.settings().items() if not k.startswith("allowed_")},
                                                              "report": report, "backend": self.legacy.capabilities(),
                                                              "boundary": "已隐藏可识别地址，分享前仍请复核。"})}
        if action == "settings-save":
            return {"state": "completed", "settings": self.store.save_settings(params)}
        if action == "settings-restore":
            return {"state": "completed", "settings": self.store.restore_settings()}
        if action == "history-compare":
            return {"state": "completed", **self.store.compare(params.get("before"), params.get("after"))}
        if action == "history-report":
            return {"state": "completed", "report": self.store.report(params.get("id"))}
        return self.legacy.run(action, params, confirmed=confirmed, preflight=gate)
