"""User-triggered desktop operations; no maintenance action runs on import."""
import os
from pathlib import Path
import platform
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
from .check_catalog import check_catalog
from .check_preferences import catalog as check_preferences_catalog
from .environment_info import cli_information, device_information
from .coverage import feature_catalog
from .isolated_browser import IsolatedBrowser
from .snapshot_archive import SnapshotArchive
from .csnap_archive import CsnapArchive
from .dmg_archive import DmgArchive
from .target_environment import FIELDS as TARGET_FIELDS, summary as environment_summary, suggest as environment_suggest, fingerprint


def _process(command, timeout=8):
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


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


def quit_account_claude():
    """Normal exit of verified desktop processes, including helper readback."""
    from .process_guard import NativeGuardIO
    io = NativeGuardIO(Path.home().resolve())
    try:
        state = io.snapshot()
        if state['unreadable']:
            return False
        if not state['targets']:
            return True
        if platform.system() == 'Windows':
            # Only numeric PID/time pairs enter this fixed command. Recheck birth
            # time before closing a window, not just a reusable process number.
            rows = ','.join('@{id=%d;born=%.6f}' % (p['pid'], p['created']) for p in state['targets'])
            code = "$items=@(" + rows + r""")
foreach($item in $items){
 $p=Get-Process -Id $item.id -ErrorAction SilentlyContinue
 if(-not $p){continue}
 $born=($p.StartTime.ToUniversalTime()-[DateTime]::SpecifyKind([DateTime]'1970-01-01','Utc')).TotalSeconds
 if([Math]::Abs($born-$item.born) -gt 0.01){exit 2}
 if($p.MainWindowHandle -ne 0){[void]$p.CloseMainWindow()}
}
"""
            if _process(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', code]).returncode != 0:
                return False
        elif platform.system() == 'Darwin':
            if _process(['/usr/bin/osascript', '-e', 'tell application "Claude" to quit']).returncode != 0:
                return False
        else:
            return False
        for _ in range(30):
            state = io.snapshot()
            if state['unreadable']:
                return False
            if not state['targets']:
                return True
            time.sleep(0.5)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return False
    return False


def force_quit_account_claude():
    """Only used after the separately disclosed per-switch force option."""
    from .process_guard import NativeGuardIO
    io = NativeGuardIO(Path.home().resolve())
    try:
        before = io.snapshot()
        if before['unreadable'] or io.stop(before['targets']) is not True:
            return False
        after = io.snapshot()
        return not after['targets'] and not after['unreadable']
    except (OSError, ValueError, KeyError):
        return False


def launch_gate(report, preferences):
    value = launch_readiness(report, preferences)
    return value["ready"], value["reasons"]


class Operations:
    def __init__(self, store, home=None, legacy=None, account_manager=None, discoverer=None, launcher=None, remedy_opener=None, maintenance=None, restart_stopper=None, environment_reader=None, region_lookup=None, process_guard=None, routing=None, network=None, client_repair=None, language_repair=None, components=None, software=None):
        self.store = store
        from .diagnostics import DiagnosticLog
        self.diagnostics = DiagnosticLog(store)
        self.environment_reader = environment_reader
        from .region_lookup import lookup_region
        self.region_lookup = region_lookup or lookup_region
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
        self.accounts = account_manager or AccountManager(state, data, stop_app=quit_account_claude,
                                                         launch_app=launch_claude, force_stop_app=force_quit_account_claude)
        self.isolated_browser = IsolatedBrowser(self.home)
        self.archives = SnapshotArchive(self.accounts, self.home/'.envscope/archive-work')
        self.csnap_archives = CsnapArchive(self.accounts, self.home/'.envscope/csnap-work')
        self.dmg_archives = DmgArchive(self.accounts, self.home/'.envscope/dmg-work')
        self.remedy_opener = remedy_opener or self._open_remedy
        self.config_remedies = ConfigRemedies(self.home, self.accounts.data_dir)
        self.maintenance = maintenance or Maintenance(store, remedies=self.config_remedies, home=self.home)
        from .timezone_service import TimezoneService
        from .inventory import collect
        self.timezone_service = TimezoneService(store,lambda:(self.environment_reader or collect)())
        self.maintenance.timezone_service=self.timezone_service
        from .process_guard import ProcessGuard
        self.process_guard = process_guard or ProcessGuard(store, self.home)
        from .routing import Routing
        self.routing = routing or Routing(store, self.home, environ={} if home is not None else None)
        from .system_network import SystemNetwork,UnavailableNetworkIO,native_network_io
        self.network=network or SystemNetwork(store,UnavailableNetworkIO() if home is not None or environment_reader is not None else native_network_io())
        from .client_repair import ClientRepair,NativeClientIO
        isolated=home is not None or environment_reader is not None
        from .wireguard import WireGuardReader
        self.wireguard_reader = (lambda: (self.environment_reader() or {}).get('network', {}).get('wireguard',
            {'platform': platform.system(), 'complete': False, 'services': [], 'error': 'unavailable'})) if environment_reader is not None else (
            (lambda: {'platform': platform.system(), 'complete': False, 'services': [], 'error': 'isolated'}) if isolated else WireGuardReader().collect)
        self.client_repair=client_repair or ClientRepair(store,NativeClientIO(self.home,environ={} if isolated else None,
            apps=(lambda:[]) if isolated else None,stop_desktop=(lambda:False) if isolated else quit_account_claude),
            root=self.home/'.envscope/client-repair' if isolated else None,
            transaction_lock=lambda:self.accounts._lock())
        from .language_repair import LanguageRepair,LanguageIO
        self.language_repair=language_repair or LanguageRepair(store,LanguageIO(
            available=False if isolated else None,close_desktop=(lambda:False) if isolated else quit_account_claude),
            root=self.home/'.envscope/client-language' if isolated else None,transaction_lock=lambda:self.accounts._lock())
        from .legacy_components import ComponentMigration, UnavailableComponents
        self.components = components or ComponentMigration(store, self.home,
            io=UnavailableComponents() if isolated else None, transaction_lock=lambda: self.accounts._lock(),
            replacements=self._component_replacements)
        from .legacy_software import SoftwareCleanup, MacSystemFiles
        self.software = software or SoftwareCleanup(self.home,self.components,
            system_files=MacSystemFiles(self.components.io) if not isolated and platform.system()=='Darwin' else None,
            pending=self.accounts._pending,transaction_lock=lambda:self.accounts._lock())
        self.solutions = SolutionPlans(self.config_remedies, self.legacy, self.discoverer,
                                      lambda proxy: self.run("proxy-diagnose", {"proxy": proxy}), self.routing,self.network,
                                      self.client_repair,self.process_guard,self.language_repair,self.components)
        from .region_setup import RegionSetup
        from .inventory import collect
        self.regions = RegionSetup(store, lambda: (self.environment_reader or collect)(), self.home,timezone_service=self.timezone_service)
        self.inspection_plans = {}

    def _component_replacements(self):
        guard, zone = self.process_guard.status(), self.timezone_service.status()
        return {'guard': guard.get('enabled') is not False or guard.get('state') == 'invalid',
                'timezone': zone.get('state') not in ('not_applicable', 'not_installed')}

    def _open_remedy(self, action):
        system = platform.system()
        directories = ('maintenance-logs','guard-logs','browser-folder','browser-logs')
        if action in ('browser-folder','browser-logs'):
            from .accounts import _safe_chain
            path = self.isolated_browser.root if action=='browser-folder' else self.isolated_browser.root.parent/'browser-cleanup-events'
            _safe_chain(path)
            if not path.is_dir():return False
        elif action in ('maintenance-logs', 'guard-logs'):
            from .accounts import _safe_chain
            path=(self.process_guard.root if action == 'guard-logs' else self.maintenance.root)/'events';_safe_chain(path)
            if not path.is_dir():return False
        elif action.startswith("config-"):
            path = self.config_remedies.backup_for_editor(action.removeprefix("config-"))
        elif action == "hosts-file":
            path = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/drivers/etc/hosts" if system == "Windows" else Path("/private/etc/hosts")
        else:
            path = None
        if system == "Windows":
            if path and action in directories:
                command=[str(Path(os.environ.get('WINDIR','C:/Windows'))/'explorer.exe'),str(path)]
            elif path:
                command = [str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/notepad.exe"), str(path)]
            else:
                uri = {"clock-settings": "ms-settings:dateandtime", "storage-settings": "ms-settings:storagesense",
                       "proxy-settings": "ms-settings:network-proxy", "locale-settings": "ms-settings:regionformatting"}.get(action)
                if not uri:
                    return False
                command = [str(Path(os.environ.get("WINDIR", "C:/Windows")) / "explorer.exe"), uri]
        elif system == "Darwin":
            command = ["/usr/bin/open", str(path)] if action in directories else ["/usr/bin/open", "-e", str(path)] if path else ["/usr/bin/open", "-b", "com.apple.systempreferences"]
        else:
            return False
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True

    def background_status(self):
        """Only read status; no account tree walk, task registration or audit lock."""
        return {'settings':self.store.settings(),'maintenance':self.maintenance.status(),
                'browser_sessions':self.isolated_browser.session_status(),
                'process_guard':self.process_guard.status(),'timezone_service':self.timezone_service.status(),
                'system_network':self.network.status(),'client_repair':self.client_repair.status(),
                'client_language':self.language_repair.status(), 'legacy_components': self.components.peek(),
                'software_cleanup':self.software.peek()}

    def catalog(self):
        try:
            accounts = self.accounts.list_accounts()
        except AccountError as error:
            accounts = {"current": None, "accounts": [], "pending": [], "error": str(error),
                        "recovery": self.accounts.recovery.status()}
        legacy = self.legacy.capabilities()
        # Retain the original macOS detailed readers separately from the
        # always-available native information panels.
        detailed = [{**entry, "id": "legacy-" + entry["id"]} for entry in legacy["actions"]
                    if entry["id"] in ("cli-info", "fingerprint")]
        for entry in legacy["actions"]:
            if entry["id"] in ("cli-info", "fingerprint"):
                entry.update(supported=True, available=True, requires_confirmation=False, reason="native_read_only")
        legacy["actions"].extend(detailed)
        browser = self.isolated_browser.capability()
        dmg = self.dmg_archives.status()
        for entry in legacy['actions']:
            if entry['id'] in ('snapshot-export', 'snapshot-import'):
                entry.update(supported=dmg['available'], available=dmg['available'], requires_confirmation=True,
                             reason=dmg['reason'], effects=['原生处理 A–D 加密 DMG；非活动槽位导出、原槽位为空时导入。只读挂载、校验复制，不运行维护核心。'])
            if entry['id'] == 'open-safe':
                entry.update(supported=True, available=browser['available'], requires_confirmation=True,
                             reason=browser['reason'], effects=['使用独立临时浏览器资料；打开前复检。关闭全部临时窗口后清理，不更改日常浏览器。'])
        desktop = getattr(self, "desktop_runtime", None)
        return {"desktop": desktop.status() if desktop else {"mode": "browser"}, "legacy": legacy, "accounts": accounts, "proxies": self.discoverer(),
                "settings": self.store.settings(), "environment": environment_summary(self.store.settings()), "history": self.store.history(), "maintenance": self.maintenance.status(), "process_guard": self.process_guard.status(),
                "config_backups": self.config_remedies.list_backups(), "learning": self.store.learning(), "checks": check_catalog(),
                'features':feature_catalog(legacy,browser), 'isolated_browser':browser, 'dmg_archives':dmg,
                'region_recovery': self.regions.public_recovery(), 'routing': self.routing.status(),
                'timezone_service': self.timezone_service.status(),
                'system_network': self.network.status(),
                'client_repair': self.client_repair.status(),
                'client_language': self.language_repair.status(),
                'legacy_components': self.components.peek(), 'software_cleanup':self.software.peek(),
                'check_config': check_preferences_catalog(self.store.settings()),
                'diagnostics': self.diagnostics.status(),
                "added_features": ["事务式账号切换", "切换前重检", "历史对比", "出口变化提示", "代理自动发现", "代理连接诊断", "脱敏诊断包", "设置恢复"]}

    def run(self, action, params, confirmed=False, report=None, preflight=None):
        started = time.monotonic()
        state = 'failed'
        try:
            result = self._run(action, params, confirmed, report, preflight)
            state = result.get('state', 'returned') if isinstance(result, dict) else 'returned'
            return result
        finally:
            # No parameters, result payloads or exception text enter this log.
            if action not in ('audit-plan', 'check-config', 'diagnostics-clear', 'desktop-show'):
                self.diagnostics.safe_record(action, state, time.monotonic() - started)

    def _run(self, action, params, confirmed=False, report=None, preflight=None):
        if not isinstance(params, dict):
            raise ValueError("invalid action parameters")
        if action in ('diagnostics-export', 'diagnostics-clear'):
            if params: raise ValueError('诊断导出与清除不接受路径或自定义字段')
            if confirmed is not True:
                return {'state': 'confirmation_required', 'reason': '仅导出脱敏检查状态与命令元数据，或清除命令诊断日志。'}
            if action == 'diagnostics-clear': return self.diagnostics.clear(confirmed)
            archive = self.diagnostics.archive(report)
            desktop = getattr(self, 'desktop_runtime', None)
            if desktop:
                import webview
                selected = desktop.window.create_file_dialog(webview.SAVE_DIALOG, allow_multiple=False,
                            save_filename=archive['filename'], file_types=('Diagnostic ZIP (*.zip)',))
                file = selected if isinstance(selected, str) else selected[0] if selected else None
                if not file: return {'state': 'cancelled', 'reason': '已取消导出，没有写入诊断包。'}
                from .diagnostics import write_archive
                return write_archive(file, archive)
            return {'state': 'completed', 'archive': archive, 'reason': '已生成脱敏 ZIP；请在浏览器中保存并复核后分享。'}
        if action in ('check-config', 'check-config-save', 'audit-plan'):
            from .check_preferences import catalog, validate, selection
            if action == 'check-config-save':
                previous = self.store.settings()['check_config']
                config = validate({**previous, **params})
                changed = any(config[key] != previous[key] for key in ('disabled', 'allow_optional_failures'))
                self.store.save_settings({'check_config': config})
                return {'state': 'completed', 'check_config': catalog(self.store.settings()),
                        'requires_retest': changed,
                        'reason': '已保存检测偏好。后续一键检查与后台巡检使用相同配置；原维护基线需重新批准。' if changed else '已保存日志设置，现有守护基线保留。'}
            if action == 'audit-plan':
                if set(params) - {'checks'}: raise ValueError('检测选择参数无效')
                return {'state': 'completed', 'checks': selection(self.store.settings(), params.get('checks'))}
            if params: raise ValueError('检测偏好读取不接受参数')
            return {'state': 'completed', 'check_config': catalog(self.store.settings())}
        if action.startswith('software-'):
            allowed={'software-status':set(),'software-plan':{'roles','restore'},'software-apply':{'plan_id'}}
            if action not in allowed or set(params)-allowed[action]:raise ValueError('旧程序清理参数无效')
            if action=='software-status':return self.software.status()
            if action=='software-plan':return self.software.prepare(params.get('roles'),restore=params.get('restore',False))
            return self.software.apply(params.get('plan_id'),confirmed)
        if action.startswith('components-'):
            allowed = {'components-status': set(), 'components-plan': {'roles', 'restore'}, 'components-apply': {'plan_id'}}
            if action not in allowed or set(params)-allowed[action]: raise ValueError('旧组件参数无效')
            if action == 'components-status':
                value=self.components.status(True)
                value['software_cleanup']=self.software.status()
                return value
            if action == 'components-plan': return self.components.prepare(params.get('roles'), restore=params.get('restore', False))
            value = self.components.apply(params.get('plan_id'), confirmed)
            if value.get('retest') or value.get('state') == 'partial': value['needs_retest'] = True
            return value
        if action.startswith('language-'):
            allowed={'language-status':set(),'language-plan':{'report_id'},'language-apply':{'plan_id'},
                     'language-restore-plan':set(),'language-restore':{'plan_id'}}
            if action not in allowed or set(params)-allowed[action]:raise ValueError('应用语言参数无效')
            if action=='language-status':return self.language_repair.status()
            if action=='language-restore-plan':return self.language_repair.prepare_restore()
            if action=='language-restore':return self.language_repair.restore(params.get('plan_id'),confirmed)
            if action=='language-apply':return self.language_repair.apply(params.get('plan_id'),confirmed,report)
            if not report or params.get('report_id')!=report.get('report_id'):
                return {'state':'retest_required','reason':'先完成新的目标检测，再预览应用语言设置。'}
            return self.language_repair.prepare(report)
        if action.startswith('client-'):
            allowed={'client-options':set(),'client-status':set(),
                     'client-plan':{'report_id','app_id','tun','restart','allow_force'},'client-apply':{'plan_id'},
                     'client-restore-plan':{'allow_force'},'client-restore':{'plan_id'}}
            if action not in allowed or set(params)-allowed[action]:raise ValueError('客户端修复参数无效')
            if action=='client-options':return self.client_repair.options()
            if action=='client-status':return self.client_repair.status()
            if action=='client-restore-plan':return self.client_repair.prepare_restore(allow_force=params.get('allow_force',False))
            if action=='client-restore':return self.client_repair.restore(params.get('plan_id'),confirmed)
            if action=='client-apply':return self.client_repair.apply(params.get('plan_id'),confirmed,report)
            if not report or params.get('report_id')!=report.get('report_id'):
                return {'state':'retest_required','reason':'先按当前目标重新检测，再预览客户端修复。'}
            return self.client_repair.prepare(report,params.get('app_id'),tun=params.get('tun',False),
                                             restart=params.get('restart',False),allow_force=params.get('allow_force',False))
        if action.startswith('system-network-'):
            allowed={'system-network-options':set(),'system-network-status':set(),
                     'system-network-plan':{'report_id','adapter_ids','flush_dns'},
                     'system-network-apply':{'plan_id'},'system-network-restore-plan':set(),
                     'system-network-restore':{'plan_id'}}
            if action not in allowed or set(params)-allowed[action]:raise ValueError('系统网络参数无效')
            if action=='system-network-options':return self.network.options()
            if action=='system-network-status':return self.network.status()
            if action=='system-network-restore-plan':return self.network.prepare_restore()
            if action=='system-network-restore':return self.network.restore(params.get('plan_id'),confirmed)
            if action=='system-network-apply':return self.network.apply(params.get('plan_id'),confirmed)
            if not report or params.get('report_id')!=report.get('report_id'):
                return {'state':'retest_required','reason':'先完成新的检测，再预览网络修复。'}
            return self.network.prepare(report,adapter_ids=params.get('adapter_ids'),flush_dns=params.get('flush_dns',False))
        if action.startswith('timezone-service-'):
            allowed={'timezone-service-status':set(),'timezone-service-plan':{'report_id','remove','restore'},
                     'timezone-service-apply':{'plan_id'},'timezone-service-recovery-plan':set(),
                     'timezone-service-recover':{'plan_id'},'timezone-service-undo-plan':set(),'timezone-service-undo':{'plan_id'}}
            if action not in allowed or set(params)-allowed[action]:raise ValueError('时区服务参数无效')
            if action=='timezone-service-status':return self.timezone_service.status()
            if action=='timezone-service-recovery-plan':return self.timezone_service.prepare_recovery()
            if action=='timezone-service-recover':return self.timezone_service.recover(params.get('plan_id'),confirmed)
            if action=='timezone-service-undo-plan':return self.timezone_service.prepare_undo()
            if action=='timezone-service-undo':return self.timezone_service.undo(params.get('plan_id'),confirmed)
            if action=='timezone-service-plan':
                if not params.get('remove',False) and (not report or params.get('report_id')!=report.get('report_id')):
                    return {'state':'retest_required','reason':'请先完成新的环境检测，再申请系统时区守护。'}
                return self.timezone_service.prepare(report,remove=params.get('remove',False),restore=params.get('restore',False))
            return self.timezone_service.apply(params.get('plan_id'),confirmed)
        if action.startswith('routing-'):
            allowed = {'routing-options': set(), 'routing-plan': {'report_id', 'group'},
                       'routing-apply': {'plan_id'}, 'routing-undo-plan': set(), 'routing-undo': {'plan_id'}}
            if action not in allowed or set(params) - allowed[action]:
                raise ValueError('路由配置参数无效')
            if action == 'routing-options':
                return self.routing.options()
            if action == 'routing-plan':
                if not report or params.get('report_id') != report.get('report_id'):
                    return {'state': 'retest_required', 'reason': '请先重新检测，再生成路由方案'}
                return self.routing.prepare(report, params.get('group'))
            if action == 'routing-apply':
                return self.routing.apply(params.get('plan_id'), report, confirmed)
            if action == 'routing-undo-plan':
                return self.routing.undo_prepare()
            return self.routing.undo(params.get('plan_id'), confirmed)
        if action in ('account-recovery-plan', 'account-recovery-apply'):
            allowed = set() if action == 'account-recovery-plan' else {'plan_id'}
            if set(params) - allowed:
                raise ValueError('invalid account recovery parameters')
            return (self.accounts.recovery.plan() if action == 'account-recovery-plan' else
                    self.accounts.recovery.apply(params.get('plan_id'), confirmed))
        if action.startswith('guard-'):
            allowed = {'guard-options': set(), 'guard-status': set(), 'guard-disable': set(), 'guard-logs': set(),
                       'guard-plan': {'report_id', 'interface'}, 'guard-enable': {'plan_id'}}
            if action not in allowed or set(params) - allowed[action]:
                raise ValueError('进程守护参数无效')
            if action == 'guard-options':
                return self.process_guard.options()
            if action == 'guard-plan':
                if not report or params.get('report_id') != report.get('report_id'):
                    return {'state': 'retest_required', 'reason': '先完成本轮检测，再生成守护方案。'}
                return self.process_guard.prepare(report, params.get('interface', ''))
            if action == 'guard-enable':
                return self.process_guard.enable(params.get('plan_id'), report, confirmed)
            if action == 'guard-disable':
                return self.process_guard.disable(confirmed)
            if action == 'guard-logs':
                opened = self.remedy_opener('guard-logs')
                return {'state': 'opened' if opened else 'unavailable', 'reason': '已打开本机守护日志目录。' if opened else '尚无日志目录；首次启用后会创建。'}
            return {'state': 'completed', 'guard': self.process_guard.status(), 'reason': '已刷新进程守护状态。'}
        if action == 'region-options':
            if params:
                raise ValueError('unexpected action parameters')
            return self.regions.options()
        if action == 'region-recovery':
            if params:
                raise ValueError('unexpected action parameters')
            return {'recovery': self.regions.public_recovery()}
        if action == 'region-settings':
            if set(params) != {'item'} or params['item'] not in ('timezone', 'locale', 'proxy'):
                raise ValueError('请选择固定的系统设置入口')
            name = {'timezone': 'clock-settings', 'locale': 'locale-settings', 'proxy': 'proxy-settings'}[params['item']]
            return {'state': 'opened' if self.remedy_opener(name) else 'unavailable', 'reason': '请在系统设置中处理后复检；打开设置不等于完成修改。'}
        if action == 'region-undo':
            if params:
                raise ValueError('unexpected action parameters')
            return self.regions.undo(confirmed)
        if action == 'inspection-plan':
            if set(params) - {'report_id', 'check_ids', 'group', 'node'}:
                raise ValueError('invalid inspection parameters')
            from .inspection import validate_selection, repair_options
            import secrets
            checks = validate_selection(params.get('check_ids'))
            if not checks:
                raise ValueError('请勾选需要处理的项目')
            settings = self.store.settings()
            if (not self.solutions._current(report) or params.get('report_id') != report['report_id'] or
                    not settings.get('environment_confirmed') or report.get('environment', {}).get('fingerprint') != fingerprint(settings)):
                return {'state': 'retest_required', 'reason': '请先检测勾选项目；仅使用本轮最新结果生成方案'}
            found = {f['id']: f for f in report['findings']}
            if any(found.get(key, {}).get('scope') == 'not-selected' for key in checks):
                return {'state': 'retest_required', 'reason': '勾选项目包含本轮未检测项，请先点击检测所选'}
            # Some target checks do not apply to the chosen use (e.g. Code auth for web).
            # Missing evidence never authorizes a write; it must not block unrelated reviewed fixes.
            missing = [key for key in checks if key not in found and key in report.get('environment', {}).get('required', [])]
            checks = [key for key in checks if key in found]
            options = repair_options(report)
            manual = [{'id': k, 'title': found[k]['title'], 'steps': options[k]['steps']} for k in checks
                      if options[k]['manual']]
            manual.extend({'id': k, 'title': k, 'steps': ['本轮未取得必需证据，请重新检测本项；未生成自动修改。']} for k in missing)
            components = [name for key, name in (('baseline.timezone', 'timezone'), ('baseline.locale', 'locale'))
                          if key in checks and found[key]['status'] != 'pass']
            if 'baseline.country' in checks and params.get('node'):
                components.append('node')
            elif 'baseline.country' in checks and found['baseline.country']['status'] != 'pass':
                manual.append({'id': 'baseline.country', 'title': '节点地区需要处理', 'steps': ['在下方读取代理组并选择目标地区的已有节点；无法读取时在代理客户端手动选择。节点名称不证明出口地区，完成后复检。']})
            region = self.regions.prepare(report, components, params.get('group', ''), params.get('node', '')) if components else {}
            if components and region.get('state') != 'planned':
                manual.append({'id': 'region', 'title': '地区配置需要手动确认', 'steps': [region.get('reason', '请重新检测')]})
            solution = self.solutions.prepare(report, check_ids=checks) if checks else {}
            for reason in solution.get('manual', []):
                manual.append({'id': 'configuration', 'title': '配置需要手动处理', 'steps': [reason]})
            effects = region.get('effects', []) + solution.get('effects', [])
            if not effects:
                return {'state': 'guided', 'manual_items': manual, 'effects': [], 'reason': '没有可直接执行的改动；请按红色项目的步骤处理后复查。' if manual else '所选项目没有可执行的修改，请根据检测结果继续。'}
            token = secrets.token_urlsafe(20)
            self.inspection_plans = {token: {'region': region.get('plan_id'), 'solution': solution.get('plan_id'),
                                            'deadline': time.monotonic() + 90, 'report_id': report['report_id'], 'fingerprint': fingerprint(settings)}}
            return {'state': 'planned', 'plan_id': token, 'effects': effects, 'manual_items': manual,
                    'reason': '确认一次后依次执行，失败则停止；保留恢复记录。配置写入后自动复检，不能自动解决的项目仍标红。' + (region.get('reason', '') if components else '')}
        if action == 'inspection-apply':
            if set(params) != {'plan_id'} or not isinstance(params['plan_id'], str):
                raise ValueError('invalid inspection plan')
            if confirmed is not True:
                return {'state': 'confirmation_required'}
            plan = self.inspection_plans.get(params['plan_id'])
            if (not plan or time.monotonic() > plan['deadline'] or not self.solutions._current(report)
                    or plan['report_id'] != report['report_id'] or plan['fingerprint'] != fingerprint(self.store.settings())):
                return {'state': 'retest_required', 'reason': '方案已过期或检测已改变，请重新生成'}
            del self.inspection_plans[params['plan_id']]
            results = []
            if plan['region']:
                results.append(self.regions.apply(plan['region'], report, True))
                if results[-1]['state'] != 'completed':
                    return {**results[-1], 'results': results, 'needs_retest': True}
            if plan['solution']:
                results.append(self.solutions.apply(plan['solution'], report, True))
            last = results[-1]
            return {'state': last['state'], 'results': results, 'needs_retest': last.get('needs_retest', True),
                    'next_review':last.get('next_review',False),
                    'backups': [b for r in results for b in r.get('backups', [])],
                    'reason': last.get('reason', '操作已返回，请复检实际结果')}
        if action == 'archive-cleanup':
            if params:
                raise ValueError('unexpected cleanup parameters')
            if confirmed is not True:
                return {'state': 'confirmation_required', 'reason': '将核实并卸载 EnvScope 的临时 DMG，随后删除其暂存副本。账号槽位、原备份和已导出文件保留。'}
            return self.dmg_archives.cleanup()
        if action in ('archive-export','archive-import','snapshot-export','snapshot-import'):
            old = action.startswith('snapshot-')
            if (set(params) != {'account','file','password'} if old else
                    not {'slot','file','password'} <= set(params) or set(params) - {'slot','file','password','format'}):
                raise ValueError('invalid archive parameters')
            format_name = 'dmg' if old else params.get('format','envsnap')
            if format_name not in ('envsnap','dmg','csnap'):
                raise ValueError('invalid archive format')
            if confirmed is not True:
                return {'state':'confirmation_required','reason':'将处理加密账号存档，密码不保存；只允许非活动槽位导出、空槽位导入。临时明文会限制读取权限并在完成后清理。'}
            archive = {'envsnap': self.archives, 'dmg': self.dmg_archives, 'csnap': self.csnap_archives}[format_name]
            slot, exporting = params['account' if old else 'slot'], action.endswith('-export')
            result = archive.export(slot,params['file'],params['password']) if exporting else archive.import_archive(params['file'],slot,params['password'])
            return {'state':'completed','result':result,'reason':'加密存档已校验并导出。请单独保管密码，丢失后无法恢复。' if exporting else '已校验并导入空槽位，未启动 Claude；登录状态是否可迁移需在实际客户端确认。',
                    'boundary': 'DMG 已检查映像校验和与复制结果；旧版没有逐文件清单，DMG 校验和不等于 .envsnap 的认证加密。' if result.get('verification') == 'legacy_image_checksum_and_copy_readback' else ''}
        if action == 'archive-choose-file':
            if not {'mode'} <= set(params) or set(params)-{'mode','format'} or params['mode'] not in ('export','import') or params.get('format','envsnap') not in ('envsnap','dmg','csnap'):
                raise ValueError('invalid file dialog mode')
            format_name = params.get('format','envsnap')
            if format_name == 'dmg' and not self.dmg_archives.status()['available']:
                return {'state':'unavailable','reason':'DMG 兼容需要 macOS，请使用 .envsnap。'}
            desktop = getattr(self,'desktop_runtime',None)
            if not desktop:
                return {'state':'unavailable','reason':'文件选择器需要独立桌面窗口；当前可填写绝对文件路径。'}
            import webview
            result = desktop.window.create_file_dialog(webview.SAVE_DIALOG if params['mode']=='export' else webview.OPEN_DIALOG,
                        allow_multiple=False, save_filename='Claude-backup.'+format_name, file_types=(f'Account archive (*.{format_name})',))
            # Cocoa save returns a string; Windows and open dialogs return a sequence.
            filename = result if isinstance(result, str) else result[0] if result else None
            return {'state':'selected' if filename else 'cancelled','file':filename}
        if action == 'browser-cleanup':
            if params:
                raise ValueError('unexpected browser parameters')
            if confirmed is not True:
                return {'state':'confirmation_required','reason':'将清理 EnvScope 中已关闭的临时浏览器资料，包括可识别的旧版资料。临时登录资料会清除；使用中或无法核实的目录保留，日常浏览器资料不受影响。'}
            return self.isolated_browser.cleanup(include_legacy=True)
        if action in ('browser-folder','browser-logs'):
            if params:
                raise ValueError('unexpected browser parameters')
            opened = self.remedy_opener(action)
            return {'state':'opened' if opened else 'unavailable',
                    'reason':('已打开临时资料目录，请先确认浏览器已退出。' if action=='browser-folder' else '已打开清理记录，记录不包含链接、代理或登录内容。') if opened else '尚未生成此目录，或系统未能打开；请先打开一次临时浏览器。'}
        if action == 'environment-location':
            return self.region_lookup(params)
        if action == 'watchdog-options':
            if params:raise ValueError('unexpected watchdog parameters')
            return self.maintenance.watchdog.options()
        if action=='maintenance-logs':
            if params:raise ValueError('unexpected log parameters')
            opened=self.remedy_opener(action)
            return {'state':'opened' if opened else 'unavailable','reason':'已打开完整日志目录。日志仅在本机保存。' if opened else '尚未生成日志目录，或系统未能打开；完成一次巡检后重试。'}
        if action == 'wireguard-options':
            if params: raise ValueError('unexpected action parameters')
            return self.wireguard_reader()
        if action == 'environment-suggest':
            if params:
                raise ValueError('unexpected action parameters')
            from .inventory import collect
            from .local_facts import cli_facts
            return environment_suggest(self.store.settings(), (self.environment_reader or collect)(), cli_facts(self.home, self.config_remedies.environ), self.discoverer())
        if action == 'environment-confirm':
            if not {'usage', 'connection_mode'} <= set(params) or set(params) - (TARGET_FIELDS - {'environment_confirmed'}):
                raise ValueError('invalid target environment fields')
            value = self.store.save_settings(params, confirm_environment=True)
            return {'state': 'completed', 'settings': value, 'environment': environment_summary(value)}
        if action in ("desktop-status", "desktop-save", "desktop-show", "desktop-hide", "app-update-check", "app-update-install", "app-update-rollback", "app-update-restart"):
            desktop = getattr(self, "desktop_runtime", None)
            return desktop.run(action, params, confirmed) if desktop else {"state": "unavailable", "reason": "此功能需要打开 EnvScope 独立软件。当前是浏览器兼容界面。"}
        if action == "permission-help":
            from .permissions import permission_help
            return permission_help(report, params, self.home, self.accounts.data_dir, confirmed)
        native_parameters = {"account-label": {"slot", "label"}, "account-switch": {"slot", "allow_force"},
                             "account-export": {"slot", "file"}, "account-import": {"slot", "file"}, "app-launch": set(), "app-restart": set(),
                             "proxy-diagnose": {"proxy"}, "support-bundle": set(), "history-compare": {"before", "after"},
                             "history-report": {"id"}, "settings-restore": set(), "learning-complete": {"version"}}
        native_parameters.update({"solution-plan": {"report_id", "check_id", "enhance_cli", "proxy"}, "solution-apply": {"plan_id"}, "solution-undo": {"backup_id"}, "solution-open": {"problem_id", "report_id"},
                                  "maintenance-plan": {"report_id", "interval", "auto_restore", "watchdog"}, "maintenance-enable": {"plan_id"},
                                  "maintenance-disable": set(), "maintenance-status": set(), "maintenance-run": set(),
                                  "maintenance-report": set(), "maintenance-undo": {"backup_id"}})
        if action in native_parameters and set(params) - native_parameters[action]:
            raise ValueError("unexpected action parameters")
        target_action = action in ('solution-plan', 'maintenance-plan') or action in ('solution-apply', 'maintenance-enable') and confirmed is True
        if target_action and not self.store.settings().get('environment_confirmed'):
            return {'state': 'retest_required', 'reason': '请先确认使用目标并完成本轮检测。'}
        if (target_action or action == 'solution-open') and report and report.get('environment'):
            if not self.store.settings().get('environment_confirmed') or report['environment']['fingerprint'] != fingerprint(self.store.settings()):
                return {'state': 'retest_required', 'reason': '目标环境已改变，请确认目标并重新检测；旧方案不再执行。'}
        gate = preflight or (lambda: launch_gate(report, self.store.settings())[0])
        if action == 'open-safe':
            if set(params) != {'url'}:
                raise ValueError('invalid browser parameters')
            if confirmed is not True:
                return {'state':'confirmation_required','reason':'将复检后打开临时浏览器，不带入原浏览器登录资料，关闭窗口后清理。'}
            from .readiness import browser_readiness
            browser_gate = preflight or (lambda: browser_readiness(report,self.store.settings()))
            return self.isolated_browser.open(params['url'], self.store.settings(), browser_gate)
        if action in ('fix','install','set-region'):
            from .regions import region_finding
            from .model import Status
            known = next((f for f in (report or {}).get('findings',[]) if f['id']=='target.region'),None)
            declared = region_finding([],self.store.settings())
            if declared.status == Status.FAIL or known and known['status']=='fail':
                return {'state':'blocked','reason':'官方地区条件不合格，未执行环境改写。地区限制不能通过修改代理、时区或语言修复。'}
        if action in ("legacy-cli-info", "legacy-fingerprint"):
            return self.legacy.run(action.removeprefix("legacy-"), params, confirmed=confirmed, preflight=gate)
        if action == "learning-complete":
            return {"state": "completed", "learning": self.store.complete_learning(params.get("version"))}
        if action in ("solution-plan", "solution-open", "maintenance-plan") and (not report or params.get("report_id") != report.get("report_id")):
            return {"state": "retest_required", "reason": "当前显示的不是本机最新检测，请重新检测后处理，不使用历史报告执行修复。"}
        if action == "solution-plan":
            return self.solutions.prepare(report, params.get("check_id"), params.get("enhance_cli", False), params.get("proxy"))
        if action == "maintenance-plan":
            return self.maintenance.prepare(report, params.get("interval", 15), params.get("auto_restore", False),params.get('watchdog'))
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
                return {"state": "completed", "result": self.accounts.switch(params.get("slot"), preflight=gate,
                                                                             allow_force=params.get('allow_force', False))}
            if action == "account-export":
                return {"state": "completed", "result": self.accounts.copy_snapshot_to(params.get("slot"), params.get("file")),
                        "note": "这是未加密的本地目录备份，不能直接公开分享。请优先使用账号页的加密存档功能。"}
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
                # The Models API supports GET, not HEAD. Anonymous 401 is an
                # expected authentication boundary, not a broken proxy.
                response = transport.get(url, headers_only=url == "https://claude.ai/")
                evidence.append({"endpoint": url, "http_status": response.status, "access": application_state(response),
                                 "elapsed_ms": round((time.monotonic() - started) * 1000), "error": response.error,
                                 "timings": response.timings, "tls_verified": response.tls_verified})
            return {"state": "completed", "evidence": evidence, "boundary": "只验证明确指定代理的无认证连接；不证明账号可用。"}
        if action == "cli-info":
            if params:
                raise ValueError("unexpected parameters")
            return cli_information(self.home)
        if action == "fingerprint":
            if params:
                raise ValueError("unexpected parameters")
            return device_information()
        if action == "support-bundle":
            return {"state": "completed", "bundle": self.diagnostics.summary(report)}
        if action == "settings-save":
            return {"state": "completed", "settings": self.store.save_settings(params)}
        if action == "settings-restore":
            return {"state": "completed", "settings": self.store.restore_settings()}
        if action == "history-compare":
            return {"state": "completed", **self.store.compare(params.get("before"), params.get("after"))}
        if action == "history-report":
            return {"state": "completed", "report": self.store.report(params.get("id"))}
        return self.legacy.run(action, params, confirmed=confirmed, preflight=gate)
