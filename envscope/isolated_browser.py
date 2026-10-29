"""Reviewed temporary Chromium sessions; never alter the user's daily profile."""
import os
from pathlib import Path
import platform
import subprocess
import threading
import uuid
from urllib.parse import urlsplit

from .accounts import AccountError, _safe_chain
from .browser_sessions import SessionStore, profile_running, start_worker


def browser_candidates(home, system=None, environ=None):
    system, env = system or platform.system(), os.environ if environ is None else environ
    if system == 'Darwin':
        apps = [('Google Chrome','Google Chrome'), ('Chromium','Chromium'), ('Microsoft Edge','Microsoft Edge'), ('Brave Browser','Brave Browser')]
        return [(name, base/(name+'.app')/'Contents/MacOS'/binary)
                for base in (Path('/Applications'), Path(home)/'Applications') for name,binary in apps]
    if system == 'Windows':
        apps = [('Microsoft Edge','Microsoft/Edge/Application/msedge.exe'), ('Google Chrome','Google/Chrome/Application/chrome.exe'),
                ('Brave','BraveSoftware/Brave-Browser/Application/brave.exe'), ('Chromium','Chromium/Application/chrome.exe')]
        return [(name, base/relative) for base in dict.fromkeys(Path(p) for p in
                (env.get('PROGRAMFILES','C:/Program Files'), env.get('PROGRAMFILES(X86)','C:/Program Files (x86)'),
                 env.get('LOCALAPPDATA',str(Path(home)/'AppData/Local')))) for name,relative in apps]
    return []


def validate_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(ord(c)<33 for c in value):
        raise ValueError('请输入完整的 HTTP / HTTPS 链接。')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError('链接格式无效。') from None
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('仅接受不含账号密码的 HTTP / HTTPS 链接。')
    return value


class IsolatedBrowser:
    def __init__(self, home, system=None, finder=None, launcher=None, running=None, worker=None):
        self.home = Path(home).resolve()
        self.system = system or platform.system()
        self.root = self.home/'.envscope/browser-sessions'
        self.finder = finder or (lambda: browser_candidates(self.home,self.system))
        self.launcher = launcher or subprocess.Popen
        self.running = running or (lambda p: profile_running(p,self.system))
        self.worker = worker if worker is not None else start_worker if launcher is None else None
        self.store = SessionStore(self.root,self.system,running=running)
        self.sessions = {}
        self.lock = threading.Lock()

    def capability(self):
        available = next(((name,path) for name,path in self.finder() if path.is_file()), None)
        sessions = self.session_status()
        return {'available':bool(available), 'browser':available[0] if available else None,
                'sessions':sessions,
                'reason':'独立临时资料、单独清理进程与重启恢复；使用中或无法核实的资料保留。' if available else '未找到已安装的 Chrome、Edge、Brave 或 Chromium。'}

    def session_status(self):
        try:
            sessions = self.store.inspect()
            sessions['worker'] = self.store.worker_status()['state']
        except (AccountError,OSError,ValueError):
            sessions = {'state':'unreadable'}
        return sessions

    def resume_cleanup(self):
        """Resume only records carrying the original explicit cleanup grant."""
        status = self.store.inspect()
        if status['sessions'] and self.worker:
            try:
                if self.store.worker_status()['state']=='running':
                    return {'state':'running','sessions':status['sessions']}
                self.worker(self.root)
                return {'state':'requested','sessions':status['sessions']}
            except (OSError,ValueError,subprocess.SubprocessError):
                return {'state':'unavailable','sessions':status['sessions']}
        return {'state':'not_needed','sessions':status['sessions']}

    def open(self, url, settings, preflight):
        url = validate_url(url)
        if settings.get('usage') not in ('desktop','web','both'):
            return {'state':'blocked','reason':'请先在使用目标中选择 Claude 网页或桌面版，并重新检测网页连接。'}
        if preflight() is not True:
            return {'state':'blocked','reason':'最新环境检查未通过，未打开临时浏览器。先处理地区与连接条件。'}
        browser = next(((name,path) for name,path in self.finder() if path.is_file()), None)
        if not browser:
            return {'state':'unavailable', 'reason':self.capability()['reason']}
        name, executable = browser
        _safe_chain(executable)
        args = [str(executable), '--no-first-run', '--no-default-browser-check',
                '--disable-sync', '--disable-extensions', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']
        mode = settings.get('connection_mode')
        if mode in ('direct','tun'):
            args.append('--no-proxy-server')
        elif settings.get('target_proxy'):
            from .transport import CurlTransport
            proxy = CurlTransport(settings['target_proxy']).proxy
            parsed = urlsplit(proxy)
            if parsed.scheme not in ('http','https') or parsed.username or parsed.password:
                raise ValueError('临时浏览器仅接受不含密码的 HTTP / HTTPS 代理。')
            args.append('--proxy-server='+proxy)
        # No language, timezone, user agent, canvas or device spoofing.
        token = uuid.uuid4().hex
        profile = self.store.create(token)
        args.insert(1,'--user-data-dir='+str(profile))
        args.append(url)
        try:
            proc = self.launcher(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except OSError:
            self.store.abandon(token)
            raise AccountError('未能启动已检测的浏览器。') from None
        self.store.launched(token,proc)
        with self.lock:
            self.sessions[token] = (profile, proc)
        self._start_reaper(token,proc)
        worker_requested = False
        if self.worker:
            try:
                self.worker(self.root)
                worker_requested = True
            except (OSError,ValueError,subprocess.SubprocessError):
                pass  # The durable record remains recoverable on next launch.
        return {'state':'started', 'reason':name+' 的临时浏览器已提交启动。登录资料不会带入日常浏览器；关闭全部临时窗口后清理。',
                'session':token,'cleanup_worker_requested':worker_requested,
                'boundary':'浏览器选项不等于防火墙隔离，需在临时窗口复查 WebRTC。'+('已请求独立清理进程，应用退出后继续检查。' if worker_requested else '独立清理进程未启动，可在下次打开应用后恢复清理。')}

    def _start_reaper(self, token, proc):
        threading.Thread(target=self._reap, args=(token,proc), daemon=True).start()

    def _reap(self, token, proc):
        try:
            proc.wait()
            self.cleanup(token)
        except (OSError, ValueError, AccountError):
            pass  # Keep profiles if process state cannot be established.

    def cleanup(self, token=None, *, include_legacy=False):
        with self.lock:
            local = {}
            for key,(profile,proc) in list(self.sessions.items()):
                try:
                    local[key] = proc.poll() is None
                except (OSError, subprocess.TimeoutExpired):
                    local[key] = None
            result = self.store.cleanup(token,allow_legacy=include_legacy,local=local)
            self.sessions = {key:value for key,value in self.sessions.items() if (self.root/key).exists()}
        result['reason'] = (f"已清理 {result['removed']} 个已关闭的临时资料；"
                            f"{result['retained']} 个仍在使用或无法确认退出，{result['unverified']} 个记录异常，均保留。"
                            +(f"另有 {result['legacy']} 个旧版资料，需确认后清理。" if result['legacy'] else ''))
        if result['retained'] or result['unverified'] or result['overflow']:
            result['boundary'] = '先退出临时浏览器的全部窗口，再重试清理。仍无法核实时，打开“临时资料目录”检查保留的会话，或查看清理记录；不要清理日常浏览器目录。'
        return result
