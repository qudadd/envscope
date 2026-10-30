"""Build standalone desktop distributions on their target operating system."""
from pathlib import Path
import os
import importlib.metadata
import json
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from envscope.app_identity import APP_ID
from .package_identity import windows_version_file, write_identity


def main():
    root = Path(__file__).resolve().parents[1]
    if platform.system() not in ("Windows", "Darwin"):
        raise SystemExit("Desktop builds target Windows or macOS only.")
    if platform.system() == 'Darwin':
        from cryptography.hazmat.bindings import _rust
        linked = subprocess.check_output(['/usr/bin/otool', '-L', _rust.__file__], text=True)
        if re.search(r'lib(?:ssl|crypto)[^/\s]*\.dylib', linked):
            raise RuntimeError('Build cryptography with OPENSSL_STATIC=1 before packaging; dynamic OpenSSL can collide with the bundled Python runtime.')
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--windowed",
               "--name", "EnvScope", "--collect-data", "envscope", "--hidden-import", "envscope._stun_worker",
               "--collect-all", "webview", "--collect-submodules", "pystray",
               "--add-data", str(root / "envscope/vendor/claude_switcher") + os.pathsep + "envscope/vendor/claude_switcher",
               "--paths", str(root),
               "--distpath", str(root / "dist" / "desktop"), "--workpath", str(root / "build" / "desktop"),
               "--specpath", str(root / "build"), str(root / "scripts" / "desktop_entry.py")]
    environment = dict(os.environ)
    command.extend(['--icon',str(root/'envscope/web'/('app.icns' if platform.system()=='Darwin' else 'app.ico'))])
    if platform.system()=='Darwin':command.extend(['--osx-bundle-identifier',APP_ID])
    if platform.system() == 'Windows':
        command.extend(['--version-file',str(windows_version_file(root/'build/windows-version.txt'))])
        from .build_windows_timezone import build as build_windows_timezone
        native=build_windows_timezone();name='timezone-helper'
        with zipfile.ZipFile(native/(name+'.payload.zip'),'w',zipfile.ZIP_DEFLATED) as archive:
            archive.write(native/(name+'.exe'),name+'.exe')
        for file in (name+'.payload.zip',name+'.json'):
            command.extend(['--add-data',str(native/file)+os.pathsep+'envscope/native-runtime'])
    if platform.system() == 'Darwin':
        from .build_timezone_worker import build
        for component in ('timezone','network','components'):
            native = build(component=component);name=component+'-helper'
            # Keep the separately signed worker byte exact. PyInstaller rewrites
            # the code signature of raw Mach-O files passed as data.
            with zipfile.ZipFile(native/(name+'.payload.zip'),'w',zipfile.ZIP_DEFLATED) as archive:
                archive.write(native/name,name)
            for file in (name+'.payload.zip',name+'.json'):
                command.extend(['--add-data',str(native/file)+os.pathsep+'envscope/native-runtime'])
    environment["PYINSTALLER_CONFIG_DIR"] = str(root / "build" / "pyinstaller-cache")
    subprocess.run(command, cwd=root, check=True, env=environment)
    app = root / "dist" / "desktop" / ("EnvScope.app" if platform.system() == "Darwin" else "EnvScope")
    if platform.system() in ('Darwin','Windows'):
        for component in (('timezone','network','components') if platform.system()=='Darwin' else ('timezone',)):
            name=component+'-helper';manifests=list(app.rglob(name+'.json'))
            binary=name+('.exe' if platform.system()=='Windows' else '')
            assert manifests, 'Native '+component+' helper missing'
            for metadata in manifests:
                expected = json.loads(metadata.read_text())
                with zipfile.ZipFile(metadata.with_name(name+'.payload.zip')) as archive:
                    assert archive.namelist()==[binary]
                    payload=archive.read(binary)
                assert hashlib.sha256(payload).hexdigest()==expected['sha256'], 'Frozen '+component+' helper bytes changed'
                assert expected['fixture'] is False, 'Acceptance helper must never ship'
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
    packages = {"ruamel.yaml", "psutil", "cryptography", "pywebview", "pystray", "Pillow", "pythonnet", "clr_loader", "proxy_tools", "typing_extensions", "cffi", "pycparser", "six", "bottle"}
    packages.update(d.metadata["Name"] for d in importlib.metadata.distributions() if d.metadata["Name"].lower().startswith("pyobjc"))
    for package in sorted(packages):
        try:
            dependency = importlib.metadata.distribution(package)
        except importlib.metadata.PackageNotFoundError:
            continue
        for file in dependency.files or []:
            if any(part.lower().startswith(("license", "copying")) for part in file.parts) and dependency.locate_file(file).is_file():
                dest = licenses / package / file.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dependency.locate_file(file), dest)
    architecture = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64"}.get(platform.machine().lower(), platform.machine().lower())
    archive = root / "dist" / ("EnvScope-" + ("macOS-" if platform.system() == "Darwin" else "Windows-") + architecture + ".zip")
    write_identity(app,platform.system())
    if platform.system() == "Darwin":
        subprocess.run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", str(app)], check=True)
        subprocess.run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)], check=True)
    else:
        shutil.make_archive(str(archive.with_suffix("")), "zip", root_dir=app.parent, base_dir=app.name)
    print("Desktop archive: " + str(archive))


if __name__ == "__main__":
    main()
