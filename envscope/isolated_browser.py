"""Reviewed temporary Chromium sessions; never alter the user's daily profile."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import threading
import uuid
from urllib.parse import urlsplit

from .accounts import AccountError, _safe_chain


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


def profile_running(profile, system):
    options = dict(capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10,
                   creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if system == 'Windows':
        code = "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);$ErrorActionPreference='Stop';@(Get-CimInstance Win32_Process | Where-Object {$_.Name -in @('chrome.exe','msedge.exe','brave.exe')} | Select-Object -ExpandProperty CommandLine) | ConvertTo-Json -Compress"
        result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code], **options)
        if result.returncode:
            return None
        try:
            commands = json.loads(result.stdout or '[]')
            commands = [commands] if isinstance(commands,str) else commands
            if not isinstance(commands,list) or any(not isinstance(c,str) or not c for c in commands):
                return None
        except ValueError:
            return None
    elif system == 'Darwin':
        result = subprocess.run(['/bin/ps','-ax','-o','command='], **options)
        if result.returncode:
            return None
        commands = result.stdout.splitlines()
    else:
        return None
    return any(str(profile).casefold() in c.casefold() for c in commands)


class IsolatedBrowser:
    def __init__(self, home, system=None, finder=None, launcher=None, running=None):
        self.home = Path(home)
        self.system = system or platform.system()
        self.root = self.home/'.envscope/browser-sessions'
        self.finder = finder or (lambda: browser_candidates(self.home,self.system))
        self.launcher = launcher or subprocess.Popen
        self.running = running or (lambda p: profile_running(p,self.system))
        self.sessions = {}
        self.lock = threading.Lock()

    def capability(self):
        available = next(((name,path) for name,path in self.finder() if path.is_file()), None)
        return {'available':bool(available), 'browser':available[0] if available else None,
                'reason':'使用独立临时资料，关闭后可清理；不伪装设备或地区。' if available else '未找到已安装的 Chrome、Edge、Brave 或 Chromium。'}

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
        _safe_chain(self.root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        token = uuid.uuid4().hex
        profile = self.root/token
        profile.mkdir(mode=0o700)
        args = [str(executable), '--user-data-dir='+str(profile), '--no-first-run', '--no-default-browser-check',
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
        args.append(url)
        try:
            proc = self.launcher(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except OSError:
            profile.rmdir()
            raise AccountError('未能启动已检测的浏览器。') from None
        with self.lock:
            self.sessions[token] = (profile, proc)
        threading.Thread(target=self._reap, args=(token,proc), daemon=True).start()
        return {'state':'started', 'reason':name+' 的临时浏览器已提交启动。登录资料不会带入日常浏览器；关闭全部临时窗口后清理。',
                'session':token, 'boundary':'浏览器选项不等于防火墙隔离；需在该临时窗口内复查 WebRTC。关闭应用或异常退出后，残留资料可能需手动清理。'}

    def _reap(self, token, proc):
        try:
            proc.wait()
            self.cleanup(token)
        except (OSError, ValueError, AccountError):
            pass  # Keep profiles if process state cannot be established.

    def cleanup(self, token=None):
        with self.lock:
            removed, retained = 0, 0
            for key,(profile,proc) in list(self.sessions.items()):
                if token and token != key:
                    continue
                try:
                    alive = proc.poll() is None or self.running(profile) is not False
                except (OSError, subprocess.TimeoutExpired):
                    alive = True
                if alive:
                    retained += 1
                    continue
                _safe_chain(profile)
                if profile.parent != self.root or profile.resolve().parent != self.root.resolve():
                    raise AccountError('临时资料路径发生变化，已停止清理。')
                shutil.rmtree(profile)
                del self.sessions[key]
                removed += 1
        return {'state':'completed', 'removed':removed, 'retained':retained,
                'reason':f'已清理 {removed} 个本次临时资料；{retained} 个仍在使用或无法确认退出，予以保留。'}
