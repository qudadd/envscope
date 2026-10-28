"""User-triggered desktop operations; no maintenance action runs on import."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

from .accounts import AccountManager, AccountError, RecoveryRequired
from .discovery import discover_proxies
from .legacy import LegacyBridge
from .report import redact
from .transport import CurlTransport, application_state
from .remedies import ConfigRemedies, SolutionPlans
from .maintenance import Maintenance
from .readiness import launch_readiness


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


def quit_claude_gracefully():
    """Request a normal exit; never escalate a failed restart into forced kill."""
    if platform.system() == "Windows":
        code = r"""$p=@(Get-Process -Name Claude -ErrorAction SilentlyContinue)
foreach($item in $p){if(-not $item.Path -or $item.Path -notmatch '\\(?:WindowsApps\\[^\\]*Claude[^\\]*|Programs\\Claude|Claude|app-[^\\]+)\\'){exit 2}}
foreach($item in $p){if($item.MainWindowHandle -ne 0){[void]$item.CloseMainWindow()}}
for($i=0;$i -lt 24;$i++){if(-not (Get-Process -Name Claude -ErrorAction SilentlyContinue)){exit 0};Start-Sleep -Milliseconds 500}
exit 1
"""
        return _process(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code], timeout=18).returncode == 0
    if platform.system() == "Darwin":
        state = _process(["/usr/bin/pgrep", "-x", "Claude"]).returncode
        if state == 1:
            return True
        if state != 0 or _process(["/usr/bin/osascript", "-e", 'tell application "Claude" to quit'], timeout=8).returncode != 0:
            return False
        for _ in range(20):
            state = _process(["/usr/bin/pgrep", "-x", "Claude"]).returncode
            if state != 0:
                return state == 1
            time.sleep(0.5)
    return False


def launch_gate(report, preferences):
    value = launch_readiness(report, preferences)
    return value["ready"], value["reasons"]


class Operations:
    def __init__(self, store, home=None, legacy=None, account_manager=None, discoverer=None, launcher=None, remedy_opener=None, maintenance=None, restart_stopper=None):
        self.store = store
        # Resolve only the trusted home alias (macOS /var temp paths or a
        # relocated home); account/configuration children remain link-checked.
        self.home = (Path(home) if home is not None else Path.home()).resolve()
        self.legacy = legacy or LegacyBridge(home=self.home)
        self.discoverer = discoverer or discover_proxies
        self.launcher = launcher or launch_claude
        self.restart_stopper = restart_stopper or quit_claude_gracefully
        state = self.home / ".claude-switcher"
        data = (Path(os.environ.get("APPDATA", str(self.home / "AppData/Roaming"))) / "Claude"
                if platform.system() == "Windows" and home is None else self.home / "AppData/Roaming/Claude"
                if platform.system() == "Windows" else self.home / "Library/Application Support/Claude")
        self.accounts = account_manager or AccountManager(state, data, stop_app=stop_claude, launch_app=launch_claude)
        self.remedy_opener = remedy_opener or self._open_remedy
        self.config_remedies = ConfigRemedies(self.home, self.accounts.data_dir)
        self.maintenance = maintenance or Maintenance(store, remedies=self.config_remedies, home=self.home)
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
                "settings": self.store.settings(), "history": self.store.history(), "maintenance": self.maintenance.status(),
                "config_backups": self.config_remedies.list_backups(), "learning": self.store.learning(),
                "added_features": ["事务式账号切换", "切换前重检", "历史对比", "出口变化提示", "代理自动发现", "代理连接诊断", "脱敏诊断包", "设置恢复"]}

    def run(self, action, params, confirmed=False, report=None, preflight=None):
        if not isinstance(params, dict):
            raise ValueError("invalid action parameters")
        native_parameters = {"account-label": {"slot", "label"}, "account-switch": {"slot"},
                             "account-export": {"slot", "file"}, "account-import": {"slot", "file"}, "app-launch": set(), "app-restart": set(),
                             "proxy-diagnose": {"proxy"}, "support-bundle": set(), "history-compare": {"before", "after"},
                             "history-report": {"id"}, "settings-restore": set(), "learning-complete": {"version"}}
        native_parameters.update({"solution-plan": {"report_id", "check_id", "enhance_cli", "proxy"}, "solution-apply": {"plan_id"}, "solution-undo": {"backup_id"}, "solution-open": {"problem_id", "report_id"},
                                  "maintenance-plan": {"report_id", "interval", "auto_restore"}, "maintenance-enable": {"plan_id"},
                                  "maintenance-disable": set(), "maintenance-status": set(), "maintenance-run": set(),
                                  "maintenance-report": set(), "maintenance-undo": {"backup_id"}})
        if action in native_parameters and set(params) - native_parameters[action]:
            raise ValueError("unexpected action parameters")
        gate = preflight or (lambda: launch_gate(report, self.store.settings())[0])
        if action == "learning-complete":
            return {"state": "completed", "learning": self.store.complete_learning(params.get("version"))}
        if action in ("solution-plan", "solution-open", "maintenance-plan") and (not report or params.get("report_id") != report.get("report_id")):
            return {"state": "retest_required", "reason": "当前显示的不是本机最新检测，请重新检测后处理，不使用历史报告执行修复。"}
        if action == "solution-plan":
            return self.solutions.prepare(report, params.get("check_id"), params.get("enhance_cli", False), params.get("proxy"))
        if action == "maintenance-plan":
            return self.maintenance.prepare(report, params.get("interval", 15), params.get("auto_restore", False))
        if action == "maintenance-enable":
            return self.maintenance.enable(params.get("plan_id"), report, confirmed)
        if action == "maintenance-disable":
            return self.maintenance.disable(confirmed)
        if action == "maintenance-status":
            return {"state": "completed", "maintenance": self.maintenance.status()}
        if action == "maintenance-report":
            return self.maintenance.latest_report()
        if action == "maintenance-run":
            return self.maintenance.run_once()
        if action == "maintenance-undo":
            if confirmed is not True:
                return {"state": "confirmation_required"}
            self.maintenance.disable(True)
            return self.config_remedies.undo(params.get("backup_id"), True)
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
        if action in ("account-switch", "account-export", "account-import", "app-launch", "app-restart"):
            if confirmed is not True:
                return {"state": "confirmation_required", "reason": "此操作会影响应用进程或账号文件"}
            if action == "account-switch":
                return {"state": "completed", "result": self.accounts.switch(params.get("slot"), preflight=gate)}
            if action == "account-export":
                return {"state": "completed", "result": self.accounts.copy_snapshot_to(params.get("slot"), params.get("file")),
                        "note": "这是未加密的本地目录备份，不能直接公开分享。加密镜像请使用 macOS 快照功能。"}
            if action == "account-import":
                return {"state": "completed", "result": self.accounts.import_snapshot_from(params.get("file"), params.get("slot"))}
            try:
                result = self.accounts.launch_checked(gate, self.launcher, restart=action == "app-restart", stop_app=self.restart_stopper)
            except RecoveryRequired:
                return {"state": "blocked", "reason": "账号资料尚待恢复，未提交启动请求。所有副本已保留，请先在账号页核对。"}
            if result["launched"]:
                reason = "已提交 Claude 桌面启动请求。请在实际窗口登录并确认收到回复。"
            elif result["stop_confirmed"] is False:
                reason = "Claude 尚未确认退出，未重开也未强制终止。请保存工作后手动退出，再使用复检后打开。"
            else:
                reason = "未确认启动请求成功。请核对官方桌面版安装；配置和账号资料没有交换。"
            return {"state": "started" if result["launched"] else "failed", "reason": reason, **result}
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
