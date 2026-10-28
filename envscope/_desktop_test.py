"""Exercise an isolated native window and tray; never start user diagnostics."""
import json
from pathlib import Path
import platform
import sys
import tempfile
import threading
import time
from unittest.mock import Mock


def main(output=None):
    import webview
    from envscope.desktop_runtime import DesktopRuntime
    from envscope.service import make_server
    from envscope.state import StateStore
    from envscope.operations import Operations
    from envscope.legacy import LegacyBridge
    result = {"platform": platform.system(), "native_window": False, "tray": False, "close_hides": False, "reopened": False, "quit": False, "network_probes": False, "user_data_changed": False}
    with tempfile.TemporaryDirectory(prefix='envscope-native-test-') as directory:
        store = StateStore(Path(directory) / 'state')
        store._write('desktop-preferences.private.json', {'check_updates': False})
        operations = Operations(store, directory, discoverer=lambda: [], legacy=LegacyBridge(home=directory, runner=Mock(side_effect=AssertionError('No vendor execution'))))
        assert operations.legacy._vendor_integrity()['verified'], 'Bundled upstream bytes and filenames must survive installation'
        server = make_server(store=store, operations=operations, auditor=Mock(side_effect=AssertionError('No public probes')))
        window = webview.create_window('EnvScope isolated test', 'http://127.0.0.1:' + str(server.server_port), width=1040, height=760, hidden=True)
        runtime = DesktopRuntime(server, window)
        operations.desktop_runtime = runtime
        window.events.closing += runtime.closing
        runtime.start_tray()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        errors = []
        def exercise():
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if window.evaluate_js("document.getElementById('native-preferences')?.hidden === false"):
                        break
                    time.sleep(0.2)
                else:
                    raise AssertionError('Native UI did not connect to the fixture server')
                result['native_window'] = True
                assert runtime.ready.wait(5), 'Tray did not initialize'
                result['tray'] = True
                ids = window.evaluate_js("[...document.querySelectorAll('[id]')].map(n=>n.id)")
                assert len(ids) == len(set(ids)), 'Duplicate DOM IDs'
                assert runtime.closing() is False
                result['close_hides'] = True
                runtime.show()
                result['reopened'] = True
                runtime.server.audit_lock.acquire()
                try:
                    assert runtime.quit() is False
                finally:
                    runtime.server.audit_lock.release()
                assert runtime.quit() is True
                result['quit'] = True
            except BaseException as error:
                errors.append(type(error).__name__ + ': ' + str(error))
                runtime.quitting = True
                window.destroy()
        try:
            webview.start(exercise, gui='edgechromium' if platform.system() == 'Windows' else 'cocoa', debug=False, private_mode=True)
        finally:
            runtime.close()
            server.shutdown()
            server.server_close()
            thread.join(3)
        result['errors'] = errors
        destination = Path(output) if output else Path('artifacts/native-smoke.json')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2), encoding='utf-8')
        if sys.stdout:
            print(json.dumps(result))
        if errors:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
