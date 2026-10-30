"""Native window lifecycle, tray and official updates. No arbitrary JS bridge."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time
from urllib.request import build_opener, ProxyHandler, Request

from .updates import AppUpdates, RELEASE, version

DEFAULTS = {"keep_running": True, "check_updates": True, "preview_updates": True}


class SingleInstance:
    def __init__(self, root):
        self.root, self.file = root, None

    def acquire(self):
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / "desktop.lock"
        if path.is_symlink() or self.root.is_symlink():
            raise ValueError("应用状态目录不能使用链接")
        self.file = path.open("a+b")
        try:
            if path.stat().st_size == 0:
                self.file.write(b"0")
                self.file.flush()
            self.file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.file.close()
            self.file = None
            return False

    def activate(self):
        try:
            file = self.root / "desktop-session.private.json"
            if file.is_symlink() or file.stat().st_size > 4096:
                return False
            data = json.loads(file.read_text(encoding="utf-8"))
            port, token = data["port"], data["token"]
            if type(port) is not int or not 1024 <= port <= 65535 or not isinstance(token, str) or not token.isascii():
                return False
            origin = "http://127.0.0.1:" + str(port)
            req = Request(origin + "/api/action", data=b'{"action":"desktop-show","params":{},"confirmed":false}', headers={"Origin": origin, "X-EnvScope-Token": token, "Content-Type": "application/json"})
            with build_opener(ProxyHandler({})).open(req, timeout=3) as response:
                return response.status == 200
        except (OSError, ValueError, KeyError):
            return False

    def close(self):
        if self.file:
            self.file.close()
            self.file = None


class DesktopRuntime:
    def __init__(self, server, window, updates=None):
        self.server, self.window = server, window
        self.updates = updates or AppUpdates(server.store)
        saved = server.store._read("desktop-preferences.private.json", {})
        if not isinstance(saved, dict):
            saved = {}
        self.preferences = {k: saved.get(k, v) if type(saved.get(k, v)) is bool else v for k, v in DEFAULTS.items()}
        self.icon, self.quitting, self.next_executable = None, False, None
        self.ready, self.stopped = threading.Event(), threading.Event()
        self.guard_attention=None
        from .guard_notifications import GuardNotifications
        self.guard_notifications=GuardNotifications(server.store,self.notify_guard)

    def notify_guard(self,value):
        self.guard_attention=value
        if self.icon:
            try:
                if getattr(self.icon,'HAS_NOTIFICATION',False):self.icon.notify(value['message'],'EnvScope 守护提醒')
                self.icon.update_menu()
            except (OSError,RuntimeError,NotImplementedError):pass
        # Details remain in local records. The fixed event only carries known IDs.
        try:self.window.run_js('document.dispatchEvent(new CustomEvent("envscope-guard-attention",{detail:'+json.dumps(value,ensure_ascii=True)+'}))')
        except (OSError,RuntimeError):pass

    def show_guard(self):
        self.show()
        self.window.run_js('document.dispatchEvent(new CustomEvent("envscope-open-guard"))')

    def poll_guard(self):
        operations=getattr(self.server,'operations',None)
        if operations is None or not self.ready.is_set():return
        lock=getattr(self.server,'audit_lock',None)
        if lock is not None and lock.locked():return
        maintenance=operations.maintenance.status();timezone=operations.timezone_service.status()
        self.guard_notifications.update(maintenance,timezone)
        if self.guard_attention and not self.guard_notifications.active:
            self.guard_attention=None
            self.window.run_js('document.dispatchEvent(new CustomEvent("envscope-guard-clear"))')

    def status(self):
        installed = self.server.store._read("desktop-install.private.json", {})
        if not isinstance(installed, dict):
            installed = {}
        return {"mode": "native", "tray": self.icon is not None and self.ready.is_set(), "preferences": dict(self.preferences),
                "updates": self.updates.status(), "can_install": bool(getattr(sys, "frozen", False)), "can_rollback": bool(installed.get("previous"))}

    def save(self, values):
        if set(values) - DEFAULTS.keys() or any(type(v) is not bool for v in values.values()):
            raise ValueError("无效的桌面偏好")
        self.preferences.update(values)
        self.server.store._write("desktop-preferences.private.json", self.preferences)
        return {"state": "completed", "desktop": self.status()}

    def show(self):
        self.window.show()
        self.window.restore()

    def closing(self):
        if self.quitting:
            return True
        if self.preferences["keep_running"] and self.icon is not None and self.ready.is_set():
            self.window.hide()
            return False
        if self.server.audit_lock.locked():
            return False
        return True

    def quit(self):
        if not self.server.audit_lock.acquire(False):
            self.show()
            return False
        self.quitting = True
        self.server.audit_lock.release()
        self.window.destroy()
        return True

    def restart(self):
        path = self.updates.installed()
        if not path:
            raise ValueError("没有已核验可启动的新版本")
        self.next_executable = path
        # Called under the service operation lock; allow that response to finish.
        def later():
            if not self.stopped.wait(0.8) and not self.quit():
                self.next_executable = None
        threading.Thread(target=later, daemon=True).start()
        return {"state": "restarting", "reason": "正在退出当前窗口并启动已核验的版本。"}

    def run(self, action, params, confirmed):
        if action == "desktop-status":
            return {"state": "completed", "desktop": self.status()}
        if action == "desktop-save":
            return self.save(params)
        if params and action != "app-update-install":
            raise ValueError("多余的桌面操作参数")
        if action == "desktop-show":
            self.show()
            return {"state": "completed"}
        if action == "desktop-hide":
            if not self.ready.is_set() or not self.icon:
                return {"state": "unavailable", "reason": "托盘入口尚未就绪，保留窗口以便退出应用。"}
            self.window.hide()
            return {"state": "completed"}
        if action == "app-update-check":
            return {"state": "completed", "desktop": {**self.status(), "updates": self.updates.check(self.preferences["preview_updates"])}}
        if action in ("app-update-install", "app-update-rollback", "app-update-restart") and not getattr(sys, "frozen", False):
            return {"state": "unavailable", "reason": "源码运行可检查版本；安装与重启需要独立桌面软件包。"}
        if action == "app-update-install":
            if set(params) != {"version"}:
                raise ValueError("请选择本次查到的版本")
            return self.updates.install(params["version"], confirmed)
        if action == "app-update-rollback":
            return self.updates.rollback(confirmed)
        if action == "app-update-restart":
            if confirmed is not True:
                return {"state": "confirmation_required", "reason": "将退出并重启 EnvScope；已启用的系统定时巡检仍按原设置运行。"}
            return self.restart()
        raise ValueError("未知桌面操作")

    def background(self):
        # This is update discovery, not implicit diagnostic/maintenance consent.
        last = None;guard_checked=0
        while not self.stopped.wait(10):
            if self.preferences["check_updates"] and (last is None or time.monotonic() - last > 24 * 3600):
                self.updates.check(self.preferences["preview_updates"])
                last = time.monotonic()
                if self.icon:
                    self.icon.update_menu()
            if time.monotonic()-guard_checked>=30:
                try:self.poll_guard()
                except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):pass
                guard_checked=time.monotonic()

    def start_tray(self):
        import pystray
        from PIL import Image, ImageDraw
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((4, 4, 60, 60), radius=12, fill="white", outline="black", width=3)
        for rect in ((19, 17, 25, 47), (25, 17, 45, 23), (25, 29, 40, 35), (25, 41, 45, 47)):
            draw.rectangle(rect, fill="black")
        def open_settings(icon, item):
            self.show()
            self.window.run_js("document.querySelector('[data-page=\"settings\"]').click()")
        def ready(icon):
            icon.visible = True
            self.ready.set()
        self.icon = pystray.Icon("EnvScope", image, "EnvScope", pystray.Menu(
            pystray.MenuItem("打开 EnvScope", lambda icon, item: self.show(), default=True),
            pystray.MenuItem(lambda item:'守护需要处理' if self.guard_attention else '查看守护状态',lambda icon,item:self.show_guard()),
            pystray.MenuItem(lambda item: "有新版可用" if self.updates.status()["state"] == "available" else "软件更新与后台设置", open_settings),
            pystray.MenuItem("退出 EnvScope", lambda icon, item: self.quit())))
        self.icon.run_detached(setup=ready)

    def close(self):
        self.stopped.set()
        if self.icon:
            self.icon.stop()


def launch_installed(executable):
    if platform.system() == "Darwin":
        command = ["/usr/bin/open", "-n", str(executable.parents[2]), "--args", "--updated"]
    else:
        command = [str(executable), "--updated"]
    subprocess.Popen(command, close_fds=True, cwd=str(executable.parent),
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def native_main(server):
    import webview
    instance = SingleInstance(server.store.root)
    if not instance.acquire():
        for _ in range(8):
            if instance.activate():
                break
            time.sleep(0.25)
        server.server_close()
        return 0
    runtime, thread = None, None
    try:
        if getattr(sys, "frozen", False) and "--updated" not in sys.argv:
            updater = AppUpdates(server.store)
            try:
                installed = updater.installed()
            except (ValueError, OSError):
                installed = None
            if installed and installed.resolve() != Path(sys.executable).resolve():
                instance.close()
                launch_installed(installed)
                return 0
        from .accounts import AccountError
        try:
            server.operations.isolated_browser.resume_cleanup()
        except (AccountError,OSError,ValueError):
            pass  # The read-only catalog exposes unreadable records for review.
        url = "http://127.0.0.1:" + str(server.server_port)
        if platform.system()=='Windows':
            import ctypes
            from .app_identity import APP_ID
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        webview.settings.update(ALLOW_DOWNLOADS=True, ALLOW_FILE_URLS=False, OPEN_EXTERNAL_LINKS_IN_BROWSER=True)
        window = webview.create_window("EnvScope", url, width=1180, height=800, min_size=(960, 640))
        runtime = DesktopRuntime(server, window)
        server.operations.desktop_runtime = runtime
        server.quit_callback = lambda: threading.Thread(target=runtime.quit, daemon=True).start()
        server.store._write("desktop-session.private.json", {"port": server.server_port, "token": server.session_token})
        window.events.closing += runtime.closing
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            runtime.start_tray()
        except (ImportError, RuntimeError, OSError):
            if runtime.icon:
                runtime.icon.stop()
            runtime.icon = None
        threading.Thread(target=runtime.background, daemon=True).start()
        webview.start(debug=False, private_mode=True, gui="edgechromium" if platform.system() == "Windows" else "cocoa")
    finally:
        if runtime:
            runtime.close()
        if thread and thread.is_alive():
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()
        instance.close()
    if runtime and runtime.next_executable:
        launch_installed(runtime.next_executable)
    return 0
