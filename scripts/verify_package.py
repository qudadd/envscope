"""Verify all vendor bytes and the desktop UI inside a built wheel or app tree."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

from envscope.legacy import MANIFEST_NAME, VENDOR_MANIFEST_SHA256


def verify(read, names):
    prefix = "envscope/vendor/claude_switcher/"
    manifest_data = read(prefix + MANIFEST_NAME)
    assert hashlib.sha256(manifest_data).hexdigest() == VENDOR_MANIFEST_SHA256, "manifest pin mismatch"
    manifest = json.loads(manifest_data)
    for path, expected in manifest["files"].items():
        payload = read(prefix + path)
        assert len(payload) == expected["size"], path
        assert hashlib.sha256(payload).hexdigest() == expected["sha256"], path
    actual = {name[len(prefix):] for name in names if name.startswith(prefix) and not name.endswith("/")}
    assert actual == set(manifest["files"]) | {MANIFEST_NAME}, "unexpected or missing vendor files"
    for path in ("index.html", "minimal.css", "app.mjs", "logic.mjs", "controls.mjs", "diagnosis.mjs", "guide.mjs", "inspection.mjs", "connection.mjs", "desktop.mjs"):
        assert read("envscope/web/" + path), "missing UI resource"
    print("Verified full pinned vendor bundle and all desktop UI resources.")


def main():
    target = Path(sys.argv[1])
    if target.is_dir():
        wheels = sorted(target.glob("*.whl"), key=lambda file: file.stat().st_mtime)
        if wheels:
            target = wheels[-1]
        else:
            verify(lambda name: (target / name).read_bytes(), [p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()])
            return
    with zipfile.ZipFile(target) as wheel:
        verify(wheel.read, wheel.namelist())


if __name__ == "__main__":
    main()
