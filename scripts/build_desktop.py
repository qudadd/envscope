"""Build standalone desktop distributions on their target operating system."""
from pathlib import Path
import os
import importlib.metadata
import json
import hashlib
import platform
import shutil
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    if platform.system() not in ("Windows", "Darwin"):
        raise SystemExit("Desktop builds target Windows or macOS only.")
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
               "--name", "EnvScope", "--collect-data", "envscope", "--hidden-import", "envscope._stun_worker",
               "--add-data", str(root / "envscope/vendor/claude_switcher") + os.pathsep + "envscope/vendor/claude_switcher",
               "--paths", str(root),
               "--distpath", str(root / "dist" / "desktop"), "--workpath", str(root / "build" / "desktop"),
               "--specpath", str(root / "build"), str(root / "scripts" / "desktop_entry.py")]
    environment = dict(os.environ)
    environment["PYINSTALLER_CONFIG_DIR"] = str(root / "build" / "pyinstaller-cache")
    subprocess.run(command, cwd=root, check=True, env=environment)
    app = root / "dist" / "desktop" / ("EnvScope.app" if platform.system() == "Darwin" else "EnvScope")
    manifests = list(app.rglob("VENDOR_MANIFEST.json"))
    if not manifests:
        raise RuntimeError("Pinned vendor bundle missing from desktop package")
    for manifest_file in manifests:
        metadata = json.loads(manifest_file.read_text(encoding="utf-8"))
        for relative, expected in metadata["files"].items():
            file = manifest_file.parent / relative
            if hashlib.sha256(file.read_bytes()).hexdigest() != expected["sha256"]:
                raise RuntimeError("Desktop vendor integrity failure: " + relative)
            if platform.system() == "Darwin" and expected["executable"]:
                file.chmod(file.stat().st_mode | 0o111)
    licenses = (app / "Contents" / "Resources" / "licenses") if platform.system() == "Darwin" else app / "licenses"
    licenses.mkdir(parents=True, exist_ok=True)
    for file in (root / "licenses").glob("*.txt"):
        shutil.copy2(file, licenses / file.name)
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(root / name, licenses / name)
    runtime_license = Path(sys.base_prefix) / "LICENSE.txt"
    if runtime_license.exists():
        shutil.copy2(runtime_license, licenses / "PYTHON-LICENSE.txt")
    distribution = importlib.metadata.distribution("pyinstaller")
    for file in distribution.files or []:
        if str(file).endswith("licenses/COPYING.txt"):
            shutil.copy2(distribution.locate_file(file), licenses / "PYINSTALLER-COPYING.txt")
    architecture = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64"}.get(platform.machine().lower(), platform.machine().lower())
    archive = root / "dist" / ("EnvScope-" + ("macOS-" if platform.system() == "Darwin" else "Windows-") + architecture + ".zip")
    if platform.system() == "Darwin":
        subprocess.run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", str(app)], check=True)
        subprocess.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)], check=True)
    else:
        shutil.make_archive(str(archive.with_suffix("")), "zip", root_dir=app.parent, base_dir=app.name)
    print("Desktop archive: " + str(archive))


if __name__ == "__main__":
    main()
