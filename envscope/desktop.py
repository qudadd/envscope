"""One-click desktop entry point, also used by frozen Windows/macOS apps."""
import sys
import threading
import webbrowser

from ._stun_worker import main as worker_main
from .service import expire_idle, make_server


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--desktop-smoke":
        from ._desktop_test import main as desktop_test
        return desktop_test(sys.argv[2])
    if len(sys.argv) > 1 and sys.argv[1] == "--maintenance-worker":
        from .maintenance import main as maintenance_main
        return maintenance_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "--stun-worker":
        worker_main(sys.argv[2:])
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "--network-worker":
        from .network_facts import main as network_main
        network_main(sys.argv[2:])
        return 0
    server = make_server()
    if "--browser" not in sys.argv:
        from .desktop_runtime import native_main
        return native_main(server)
    thread = threading.Thread(target=expire_idle, args=(server,), daemon=True)
    thread.start()
    url = "http://127.0.0.1:" + str(server.server_port)
    try:
        webbrowser.open(url)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.desktop_stopped = True
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
