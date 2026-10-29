"""Verify all vendor bytes and the desktop UI inside a built wheel or app tree."""
import hashlib
import json
from email.parser import BytesParser
from pathlib import Path
import sys
import zipfile

from envscope.legacy import MANIFEST_NAME, VENDOR_MANIFEST_SHA256
from envscope import __version__


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
    for path in ("index.html", "minimal.css", "app.mjs", "logic.mjs", "controls.mjs", "diagnosis.mjs", "guide.mjs", "inspection.mjs", "connection.mjs", "desktop.mjs", "target.mjs", "coverage.mjs", "region_choices.mjs", "watchdog_ui.mjs", "process_guard_ui.mjs", "account_recovery_ui.mjs", "routing_ui.mjs", "timezone_ui.mjs", "network_ui.mjs", "client_ui.mjs"):
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
        metadata=[n for n in wheel.namelist() if n.endswith('.dist-info/METADATA')]
        assert len(metadata)==1,'Missing or ambiguous package metadata'
        values=BytesParser().parsebytes(wheel.read(metadata[0]))
        assert values['Name']=='envscope' and values['Version']==__version__,'Wheel and app versions differ'
        verify(wheel.read, wheel.namelist())


if __name__ == "__main__":
    main()
