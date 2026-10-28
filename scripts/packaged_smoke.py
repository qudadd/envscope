"""Exercise frozen STUN worker over loopback, including windowless Windows IO."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from envscope import __release__


def main():
    executable = Path(sys.argv[1]).resolve()
    internal = executable.parent / "_internal" / "envscope" / "web"
    if internal.exists():
        assert "一键检测" in (internal / "index.html").read_text(encoding="utf-8")
        assert (internal / "minimal.css").exists()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, tempfile.TemporaryDirectory() as directory:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(8)
        def respond():
            data, remote = sock.recvfrom(1024)
            address = bytes(v ^ k for v, k in zip(bytes((8, 8, 8, 8)), bytes((0x21, 0x12, 0xA4, 0x42))))
            attr = struct.pack("!HHBBH", 0x0020, 8, 0, 1, 1234 ^ 0x2112) + address
            response = struct.pack("!HHI", 0x0101, len(attr), 0x2112A442) + data[8:20] + attr
            sock.sendto(response, remote)
        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        output = Path(directory) / "worker.private.json"
        result = subprocess.run([str(executable), "--stun-worker", "127.0.0.1", str(sock.getsockname()[1]), "4", "2", str(output)],
                                capture_output=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == 0, "frozen worker failed"
        assert json.loads(output.read_text())["ip"] == "8.8.8.8"
        thread.join(timeout=2)
        network_output = Path(directory) / "network.private.json"
        result = subprocess.run([str(executable), "--network-worker", "--offline", str(network_output)], capture_output=True,
                                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == 0, "frozen network worker failed"
        assert json.loads(network_output.read_text())["mode"] == "offline"
        result = subprocess.run([str(executable), "--maintenance-worker", "--check-runtime"], capture_output=True,
                                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == 0, "frozen maintenance worker imports failed"
        desktop_output = Path(directory) / "native.private.json"
        result = subprocess.run([str(executable), "--desktop-smoke", str(desktop_output)], capture_output=True,
                                timeout=50, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        evidence = Path('artifacts/native-smoke.json')
        evidence.parent.mkdir(parents=True, exist_ok=True)
        native = json.loads(desktop_output.read_text()) if desktop_output.exists() else {'errors': ['native process returned no evidence'], 'returncode': result.returncode}
        evidence.write_text(json.dumps(native, indent=2), encoding='utf-8')
        if result.returncode or native.get('errors'):
            print(json.dumps(native))
            print(result.stderr.decode('utf-8', errors='replace')[-12000:])
        assert result.returncode == 0 and desktop_output.exists(), "frozen native window/tray smoke failed"
        assert not native['errors'] and all(native[key] for key in ('native_window', 'tray', 'close_hides', 'reopened', 'quit')), native
        assert native['release'] == __release__, 'Built executable release does not match the source'
    print("Packaged worker and local resource checks passed; no public network was contacted.")


if __name__ == "__main__":
    main()
