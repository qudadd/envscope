"""Official-release updates, staged beside the running app and never in place."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import threading
import time
import unicodedata
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener
import uuid
import zipfile

from . import __version__, __release__
from .legacy import UPSTREAM_COMMIT

REPOSITORY = "qudadd/envscope"
RELEASE = __release__
API = "https://api.github.com/repos/" + REPOSITORY
HOSTS = {"api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
MAX_ARCHIVE = 350 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()


def version(tag):
    if not isinstance(tag, str):
        raise ValueError("无法识别官方版本号")
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?", tag or "")
    if not m:
        raise ValueError("无法识别官方版本号")
    return tuple(map(int, m.group(1, 2, 3))) + ({"alpha": 0, "beta": 1, "rc": 2, None: 3}[m[4]], int(m[5] or 0))


def allowed_url(url):
    p = urlsplit(url)
    return p.scheme == "https" and p.hostname in HOSTS and not p.username and not p.password and p.port in (None, 443)


class ReleaseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise ValueError("更新下载跳转到了未批准的地址")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit, destination=None):
    if not allowed_url(url):
        raise ValueError("只允许官方 GitHub 发布地址")
    req = Request(url, headers={"User-Agent": "EnvScope/" + __version__, "Accept": "application/vnd.github+json" if url.startswith("https://api.github.com/") else "application/octet-stream"})
    # TLS verification remains enabled; the OS/user proxy is respected.
    with build_opener(ReleaseRedirect()).open(req, timeout=30) as response:
        if response.status != 200:
            raise ValueError("更新服务未返回有效结果")
        output = destination.open("xb") if destination else None
        chunks, size, deadline = [], 0, time.monotonic() + 180
        try:
            while True:
                block = response.read(65536)
                if not block:
                    break
                size += len(block)
                if size > limit or time.monotonic() > deadline:
                    raise ValueError("更新下载超过大小或时间限制")
                if output:
                    output.write(block)
                else:
                    chunks.append(block)
        finally:
            if output:
                output.close()
    return size if destination else b"".join(chunks)


def asset_name(system=None, machine=None):
    system, machine = system or platform.system(), (machine or platform.machine()).lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if system == "Windows" and arch == "x64":
        return "EnvScope-Windows-x64.zip"
    if system == "Darwin" and arch:
        return "EnvScope-macOS-" + arch + ".zip"
    raise ValueError("当前系统架构暂无可自动安装的软件包")


def safe_extract(archive, destination, system):
    """Accept only the app root; validate all paths before extracting anything."""
    root_name = "EnvScope.app" if system == "Darwin" else "EnvScope"
    with zipfile.ZipFile(archive) as z:
        files, links, seen, size = [], [], set(), 0
        if len(z.infolist()) > 20000:
            raise ValueError("更新包文件数量异常")
        for item in z.infolist():
            if item.filename.startswith("__MACOSX/"):
                continue
            filename = item.filename
            # macOS ditto sometimes writes UTF-8 filenames without ZIP's UTF-8
            # bit. Keep the same normalization used by release verification.
            if not item.flag_bits & 0x800:
                try:
                    filename = filename.encode('cp437').decode('utf-8')
                except UnicodeError:
                    pass
            path = PurePosixPath(unicodedata.normalize('NFC', filename))
            if not path.parts or path.parts[0] != root_name or path.is_absolute() or any(p in ("..", ".") or ":" in p or "\\" in p or p.rstrip(" .") != p or any(ord(c) < 32 for c in p) for p in path.parts):
                raise ValueError("更新包包含不安全路径")
            key = str(path).casefold()
            if key in seen:
                raise ValueError("更新包包含重复路径")
            seen.add(key)
            size += item.file_size
            if size > 1200 * 1024 * 1024:
                raise ValueError("更新包展开后过大")
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                if system != "Darwin" or item.file_size > 2048:
                    raise ValueError("更新包链接无效")
                target = z.read(item).decode("utf-8")
                actual = (destination / str(path)).parent / target
                if Path(target).is_absolute() or not actual.resolve().is_relative_to((destination / root_name).resolve()):
                    raise ValueError("更新包链接越过应用目录")
                links.append((path, target))
            elif not item.is_dir() and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise ValueError("更新包文件类型无效")
            else:
                files.append((item, path, mode))
        link_paths = {str(p).casefold() for p, _ in links}
        for _, path, _ in files:
            if any(str(p).casefold() in link_paths for p in path.parents):
                raise ValueError("更新包试图通过链接写入文件")
        for path, _ in links:
            if any(str(p).casefold() in link_paths for p in path.parents):
                raise ValueError("更新包包含嵌套链接")
        for item, path, mode in files:
            out = destination / str(path)
            if item.is_dir():
                out.mkdir(parents=True, exist_ok=True)
            else:
                out.parent.mkdir(parents=True, exist_ok=True)
                with z.open(item) as source, out.open("xb") as target:
                    shutil.copyfileobj(source, target)
                if system == "Darwin":
                    out.chmod(0o755 if mode & 0o111 else 0o644)
        for path, target in links:
            out = destination / str(path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.symlink_to(target)
        for path, _ in links:
            if not (destination / str(path)).resolve().is_relative_to((destination / root_name).resolve()):
                raise ValueError("更新包链接链越过应用目录")
    app = destination / root_name
    exe = app / "Contents/MacOS/EnvScope" if system == "Darwin" else app / "EnvScope.exe"
    if not exe.is_file() or exe.is_symlink():
        raise ValueError("更新包缺少主程序")
    with exe.open("rb") as file:
        magic = file.read(4)
    if (system == "Windows" and not magic.startswith(b"MZ")) or (system == "Darwin" and magic not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf")):
        raise ValueError("更新包主程序格式无效")
    return exe


class AppUpdates:
    def __init__(self, store, downloader=fetch, system=None, machine=None):
        self.store, self.downloader = store, downloader
        self.system, self.machine = system or platform.system(), machine or platform.machine()
        self.lock = threading.Lock()
        self.candidate = None
        self.state = {"state": "not_checked", "current": RELEASE, "source": "https://github.com/" + REPOSITORY + "/releases"}

    def status(self):
        return dict(self.state)

    def check(self, preview=True):
        if not self.lock.acquire(False):
            return {**self.status(), "busy": True}
        try:
            releases = json.loads(self.downloader(API + "/releases?per_page=30", 2097152))
            if not isinstance(releases, list):
                raise ValueError("官方发布列表格式无效")
            found = []
            name = asset_name(self.system, self.machine)
            for r in releases:
                if not isinstance(r, dict) or r.get("draft") is not False or r.get("prerelease") and not preview:
                    continue
                try:
                    order = version(r.get("tag_name"))
                except (ValueError, TypeError):
                    continue
                if order <= version(RELEASE):
                    continue
                assets = r.get("assets", [])
                if not isinstance(assets, list) or any(not isinstance(a, dict) for a in assets):
                    continue
                package = next((a for a in assets if a.get("name") == name and a.get("state") == "uploaded"), None)
                sums = next((a for a in assets if a.get("name") in ("SHA256SUMS", "SHA256SUMS.txt") and a.get("state") == "uploaded"), None)
                if not package or not sums:
                    continue
                expected = "https://github.com/" + REPOSITORY + "/releases/download/" + r["tag_name"] + "/"
                if package.get("browser_download_url") != expected + name or sums.get("browser_download_url") != expected + sums["name"]:
                    continue
                if type(package.get("size")) is not int or not 0 < package["size"] <= MAX_ARCHIVE or not re.fullmatch(r"sha256:[a-f0-9]{64}", package.get("digest", "")):
                    continue
                found.append((order, r, package, sums))
            candidate = max(found, key=lambda v: v[0]) if found else None
            self.candidate = candidate
            self.state = {"state": "available" if candidate else "up_to_date", "current": RELEASE, "checked_at": time.time(), "source": "https://github.com/" + REPOSITORY + "/releases"}
            if candidate:
                _, r, package, sums = candidate
                self.state.update(version=r["tag_name"], size=package["size"], notes=str(r.get("body", ""))[:6000],
                                  release_url="https://github.com/" + REPOSITORY + "/releases/tag/" + r["tag_name"])
            try:
                upstream = json.loads(self.downloader("https://api.github.com/repos/YOURSJEYO/claude-switcher/commits/HEAD", 262144))
                if not isinstance(upstream, dict):
                    raise ValueError("无效的上游版本信息")
                sha = upstream.get("sha", "")
                if re.fullmatch(r"[a-f0-9]{40}", sha):
                    self.state["upstream"] = {"revision": sha, "bundled": UPSTREAM_COMMIT, "changed": sha != UPSTREAM_COMMIT,
                                              "note": "上游差异由 EnvScope 测试后随软件发布；不会自动替换维护核心。"}
            except (OSError, ValueError, TypeError):
                self.state["upstream"] = {"note": "上游状态暂未取得，可稍后重试。"}
        except (OSError, ValueError, TypeError):
            self.candidate = None
            self.state = {"state": "unavailable", "current": RELEASE, "reason": "暂时无法核验官方更新。检查网络后重试；当前版本可继续使用。"}
        finally:
            self.lock.release()
        return self.status()

    def install(self, tag, confirmed=False):
        if confirmed is not True:
            return {"state": "confirmation_required", "reason": "将从 qudadd/envscope 下载对应系统的软件包，核对 GitHub SHA256 与发布校验表，安装到当前用户目录。保留旧版；完成后由你确认重启。"}
        if not self.lock.acquire(False):
            return {"state": "busy"}
        staging = None
        try:
            if not self.candidate or self.candidate[1]["tag_name"] != tag or time.time() - self.state.get("checked_at", 0) > 3600:
                raise ValueError("请重新检查更新，再选择本次核验的版本")
            _, release, package, sums = self.candidate
            versions = self.store.root / "updates/versions"
            versions.mkdir(parents=True, exist_ok=True)
            if versions.is_symlink() or not versions.resolve().is_relative_to(self.store.root.resolve()):
                raise ValueError("更新目录不能指向用户资料目录之外")
            destination = versions / tag
            if destination.exists():
                raise ValueError("这个版本已下载；请重启或先检查已安装版本")
            staging = versions / (".stage-" + uuid.uuid4().hex)
            staging.mkdir()
            checksum_text = self.downloader(sums["browser_download_url"], 65536).decode("utf-8")
            matches = re.findall(r"(?m)^([a-f0-9]{64}) [ *]" + re.escape(package["name"]) + r"\r?$", checksum_text)
            if matches != [package["digest"][7:]]:
                raise ValueError("GitHub 摘要与发布校验表不一致，更新已停止")
            archive = staging / "download.zip"
            size = self.downloader(package["browser_download_url"], min(package["size"] + 1, MAX_ARCHIVE), archive)
            if size != package["size"] or sha256(archive) != matches[0]:
                raise ValueError("下载文件校验失败，旧版本保持可用")
            try:
                exe = safe_extract(archive, staging, self.system)
            except (zipfile.BadZipFile, UnicodeError, RuntimeError) as error:
                raise ValueError("更新包不能安全展开，旧版本保持可用") from error
            relative = exe.relative_to(staging)
            digest = sha256(exe)
            archive.unlink()
            os.replace(staging, destination)
            staging = None
            previous = self.store._read("desktop-install.private.json", {})
            if not isinstance(previous, dict):
                previous = {}
            receipt = {"version": tag, "executable": str((destination / relative).relative_to(self.store.root)), "sha256": digest}
            self.store._write("desktop-install.private.json", {"active": receipt, "previous": previous.get("active")})
            self.state = {**self.state, "state": "ready", "reason": "新版已核验并安装。可以重启 EnvScope；账号、网络与检测偏好没有修改。"}
            return self.status()
        finally:
            if staging and staging.resolve().is_relative_to((self.store.root / "updates/versions").resolve()) and staging.name.startswith(".stage-"):
                shutil.rmtree(staging)
            self.lock.release()

    def installed(self, previous=False):
        record = self.store._read("desktop-install.private.json", {})
        receipt = record.get("previous" if previous else "active") if isinstance(record, dict) else None
        if not isinstance(receipt, dict):
            return None
        version(receipt.get("version"))
        if not isinstance(receipt.get("executable"), str):
            raise ValueError("已安装版本的路径无效")
        path = self.store.root / receipt.get("executable", "")
        if path.is_symlink() or not path.resolve().is_relative_to((self.store.root / "updates/versions" / receipt["version"]).resolve()) or not path.is_file():
            raise ValueError("已安装版本的路径无效")
        if sha256(path) != receipt.get("sha256"):
            raise ValueError("已安装的主程序发生变化，请重新下载")
        return path

    def rollback(self, confirmed=False):
        if confirmed is not True:
            return {"state": "confirmation_required", "reason": "将启动指向上一个已核验的软件版本；保留当前版本与用户资料。"}
        if not self.installed(previous=True):
            raise ValueError("没有可回退的软件版本")
        data = self.store._read("desktop-install.private.json", {})
        self.store._write("desktop-install.private.json", {"active": data["previous"], "previous": data["active"]})
        return {"state": "ready", "reason": "已选择上一个版本，重启 EnvScope 后生效。"}
