"""Native macOS compatibility with claude-switcher's encrypted root-layout DMG.

Only hdiutil is invoked, never a vendor script. Mounts are read-only. Workspaces
survive a failed/uncertain detach and require explicit cleanup on the next run.
DMG image checksums are not authenticated encryption; .envsnap remains the
cross-platform AES-GCM format. Neither format exports the system keychain.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile

from .accounts import AccountError, _safe_chain, _safe_entry, _file_signature, validate_slot
from .snapshot_archive import LIMIT, FILES, CHUNK, _path

MARKER = '.claude-switcher-snapshot.json'
SYSTEM_DIRS = {'.fseventsd', '.Trashes', '.Spotlight-V100', '.TemporaryItems'}
WORK = re.compile(r'dmg-[a-z0-9_]{8,32}\Z')
DEVICE = re.compile(r'/dev/disk[0-9]+(?:s[0-9]+)*\Z')


def _password(value, exporting=False):
    if (not isinstance(value, str) or not (12 if exporting else 1) <= len(value) <= 1024
            or any(c in value for c in '\0\r\n')):
        raise ValueError('DMG 导出密码至少 12 字符；导入使用原密码。密码不能含换行或空字符。')
    # Match the pinned upstream's printf '%s\\n' | hdiutil -stdinpass protocol.
    return value.encode('utf-8') + b'\n'


def _slot(value):
    value = validate_slot(value)
    if value not in ('A', 'B', 'C', 'D'):
        raise AccountError('原版 DMG 兼容格式仅支持 A、B、C、D，且导入槽位须与存档一致。其他槽位请使用 .envsnap。')
    return value


def _tree(root, image=False):
    """Bound before hashing/copying, and never follow special entries."""
    _safe_chain(root)
    result, total, todo = {'.': ['directory']}, 0, [root]
    device = root.stat().st_dev
    while todo:
        directory = todo.pop()
        for path in directory.iterdir():
            _safe_entry(path)
            info = path.lstat()
            if info.st_dev != device:
                raise AccountError('存档含嵌套挂载点，已停止。')
            if directory == root and path.name in SYSTEM_DIRS | {MARKER}:
                if not image:
                    raise AccountError('账号包含 DMG 保留名称，请改用 .envsnap。')
                if path.name in SYSTEM_DIRS and not stat.S_ISDIR(info.st_mode):
                    raise AccountError('DMG 系统目录格式异常。')
                continue
            name = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                result[name] = ['directory']
                todo.append(path)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                total += info.st_size
                result[name] = ['file', info.st_size]
            else:
                raise AccountError('DMG 含链接或特殊文件，未导入。')
            if total > LIMIT or len(result) > FILES:
                raise AccountError('DMG 内容超过 8 GiB 或 200000 项上限。')
    for name, entry in result.items():
        if entry[0] == 'file':
            result[name] = list(_file_signature(root/name))
    return result


def _copy_image(source, destination):
    _safe_chain(source)
    info = source.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= LIMIT:
        raise AccountError('DMG 必须为普通单文件，大小不超过 8 GiB。')
    before = _file_signature(source)
    with source.open('rb') as inp, destination.open('xb') as out:
        shutil.copyfileobj(inp, out, CHUNK)
        out.flush()
        os.fsync(out.fileno())
    destination.chmod(0o600)
    if before != _file_signature(destination) or before != _file_signature(source):
        raise AccountError('读取期间 DMG 发生变化，操作已停止。')


class DiskImages:
    """Fixed local system executable; passwords never enter argv or error text."""
    def run(self, args, password=None, timeout=120, plist=False):
        try:
            value = subprocess.run(['/usr/bin/hdiutil', *map(str, args)],
                                   input=password or b'', capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            raise AccountError('macOS 磁盘映像操作未完成；临时资料会保留供清理检查。') from None
        if value.returncode:
            raise AccountError('DMG 操作失败：请核对密码、文件完整性和可用磁盘空间。')
        if len(value.stdout) > 4*1024**2:
            raise AccountError('磁盘映像工具返回的信息过大。')
        if plist:
            try:
                result = plistlib.loads(value.stdout)
                if not isinstance(result, dict):
                    raise ValueError()
                return result
            except (ValueError, plistlib.InvalidFileException):
                raise AccountError('磁盘映像工具未返回可验证的结构化结果。') from None

    def encrypted(self, image):
        value = self.run(['isencrypted', '-plist', image], plist=True)
        if value.get('encrypted') is not True:
            raise AccountError('该 DMG 未确认加密，未作为加密账号备份处理。')

    def verify(self, image, password):
        self.encrypted(image)
        self.run(['verify', '-stdinpass', image], password, timeout=300)

    def create(self, source, image, slot, password):
        self.run(['create', '-srcfolder', source, '-volname', 'ClaudeSnapshot-'+slot,
                  '-encryption', 'AES-256', '-stdinpass', image], password, timeout=600)

    def attach(self, image, mount, password):
        value = self.run(['attach', '-stdinpass', '-nobrowse', '-noautoopen', '-readonly',
                          '-mountpoint', mount, '-plist', image], password, plist=True)
        entities = value.get('system-entities', [])
        if not any(e.get('mount-point') == str(mount) and DEVICE.fullmatch(e.get('dev-entry', '')) for e in entities):
            raise AccountError('DMG 未挂载到已批准的临时目录。')

    def attached(self, image):
        value = self.run(['info', '-plist'], plist=True)
        if not isinstance(value.get('images'), list):
            raise AccountError('无法核实临时 DMG 是否仍然挂载。')
        return [entry for entry in value['images'] if entry.get('image-path') == str(image)]

    def detach(self, image, mount):
        for entry in self.attached(image):
            entities = entry.get('system-entities', [])
            devices = [e.get('dev-entry', '') for e in entities]
            if not devices or any(not DEVICE.fullmatch(d) for d in devices):
                raise AccountError('临时磁盘设备信息异常；请在磁盘工具中检查。')
            if any(e.get('mount-point') not in (None, str(mount)) for e in entities):
                raise AccountError('临时映像挂载位置已改变；保留资料供手动检查。')
            # The whole-disk entity is first in hdiutil's structured image list.
            whole = next((d for d in devices if re.fullmatch(r'/dev/disk[0-9]+', d)), None)
            if not whole:
                raise AccountError('无法确认临时映像的完整设备，未尝试强制卸载。')
            self.run(['detach', whole], timeout=30)
        if self.attached(image):
            raise AccountError('临时映像仍在挂载，未删除暂存目录。')


class DmgArchive:
    def __init__(self, manager, work_root, *, system=None, disk=None):
        self.manager, self.work_root = manager, Path(work_root).absolute()
        self.system, self.disk = system or platform.system(), disk or DiskImages()

    def _event(self, transaction, phase, operation, slot=None):
        from .event_log import append_event
        append_event(self.work_root/'events', {'at': datetime.now(timezone.utc).isoformat(),
                     'kind': 'dmg_archive', 'transaction': transaction, 'phase': phase,
                     'operation': operation, 'slot': slot})

    def status(self):
        try:
            _safe_chain(self.work_root)
            pending = sorted(p.name for p in self.work_root.glob('dmg-*')) if self.work_root.exists() else []
            return {'available': self.system == 'Darwin', 'pending': pending,
                    'reason': '检测到未清理的 DMG 暂存资料；请先检查并清理。' if pending else
                              'macOS 原生兼容原版 A–D 加密 DMG。' if self.system == 'Darwin' else
                              'DMG 兼容需要 macOS；本机请使用 .envsnap。'}
        except (OSError, AccountError):
            return {'available': False, 'pending': ['unreadable'], 'reason': 'DMG 暂存目录不可读取，请手动检查权限。'}

    @contextmanager
    def _lock(self):
        if self.system != 'Darwin':
            raise AccountError('原版 DMG 兼容仅支持 macOS，请使用 .envsnap。')
        _safe_chain(self.work_root)
        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.work_root.chmod(0o700)
        lock = self.work_root/'.lock'
        _safe_chain(lock)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'r+b') as stream:
            if os.fstat(fd).st_nlink != 1:
                raise AccountError('DMG 锁文件异常。')
            if not stream.read(1):
                stream.write(b'0'); stream.flush()
            stream.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise AccountError('另一个 DMG 操作正在进行。') from None
            try:
                yield
            finally:
                stream.seek(0)
                if os.name == 'nt':
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)

    def _clean(self, root):
        _safe_chain(root)
        if root.parent != self.work_root or not WORK.fullmatch(root.name):
            raise AccountError('暂存目录名称异常，未清理。')
        self.disk.detach(root/'archive.dmg', root/'mount')
        # Even when hdiutil reports no image, never traverse a surviving mount.
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                child = Path(directory)/name
                _safe_entry(child)
                if os.path.ismount(child) or child.lstat().st_dev != root.stat().st_dev:
                    raise AccountError('暂存目录仍包含挂载点，未清理。')
        shutil.rmtree(root)

    def cleanup(self):
        with self._lock():
            pending = self.status()['pending']
            for name in pending:
                self._clean(self.work_root/name)
                self._event(name, 'cleanup_complete', 'cleanup')
            return {'state': 'completed', 'reason': f'已核实卸载并清理 {len(pending)} 个 DMG 暂存目录。账号槽位保持原状。'}

    @contextmanager
    def _workspace(self, operation, slot):
        with self._lock():
            if self.status()['pending']:
                raise AccountError('有上次遗留的 DMG 暂存资料，请先点击“检查并清理暂存”。')
            root = Path(tempfile.mkdtemp(prefix='dmg-', dir=self.work_root))
            root.chmod(0o700)
            try:
                self._event(root.name, 'started', operation, slot)
                yield root
                self._event(root.name, 'data_committed', operation, slot)
            except BaseException:
                self._event(root.name, 'operation_failed', operation, slot)
                raise
            finally:
                try:
                    self._clean(root)
                    self._event(root.name, 'cleanup_complete', operation, slot)
                except (OSError, AccountError):
                    self._event(root.name, 'cleanup_needed', operation, slot)
                    raise AccountError('DMG 暂存清理尚未完成，已保留资料。请检查账号/导出文件状态，再点击“检查并清理暂存”；仍失败时使用 macOS 磁盘工具推出 ClaudeSnapshot 映像。') from None

    def _read_profile(self, root, slot, password):
        image, mount = root/'archive.dmg', root/'mount'
        self.disk.verify(image, password)
        mount.mkdir(mode=0o700)
        self.disk.attach(image, mount, password)
        marker = mount/MARKER
        _safe_chain(marker)
        info = marker.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 32*1024**2:
            raise AccountError('DMG 账号标记无效。')
        try:
            value = json.loads(marker.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError):
            raise AccountError('DMG 账号标记无法解析。') from None
        if (not isinstance(value, dict) or value.get('format') != 'claude-switcher-snapshot'
                or type(value.get('version')) is not int or value['version'] != 1 or value.get('account') != slot):
            raise AccountError('DMG 格式或账号槽位不匹配。请选择存档原来的 A、B、C 或 D。')
        manifest = _tree(mount, image=True)
        extra = value.get('envscope')
        if extra is not None and (not isinstance(extra, dict) or type(extra.get('version')) is not int or extra.get('version') != 1 or extra.get('files') != manifest):
            raise AccountError('DMG 文件清单或校验值不一致，未导入。')
        profile = root/'restored'
        profile.mkdir(mode=0o700)
        for name, entry in sorted(manifest.items()):
            if name == '.':
                continue
            destination = profile/name
            if entry[0] == 'directory':
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(mount/name, destination, follow_symlinks=False)
        if _tree(profile) != manifest or _tree(mount, image=True) != manifest:
            raise AccountError('DMG 资料复制校验未通过。')
        self.disk.detach(image, mount)
        return profile, manifest, extra is not None

    def export(self, slot, filename, password):
        slot, password, target = _slot(slot), _password(password, True), _path(filename)
        if target.suffix.lower() != '.dmg' or target.exists() or not target.parent.is_dir():
            raise AccountError('请选择尚不存在的 .dmg 文件及已有目录。')
        for managed in (self.manager.state_dir, self.manager.data_dir, self.work_root):
            if target.is_relative_to(managed):
                raise AccountError('DMG 不能导出到账号或暂存目录内。')
        with self._workspace('export', slot) as root:
            source, image = root/'profile', root/'archive.dmg'
            self.manager.copy_snapshot_to(slot, source)
            manifest = _tree(source)
            metadata = {'format': 'claude-switcher-snapshot', 'version': 1, 'account': slot,
                        'created': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                        'envscope': {'version': 1, 'files': manifest}}
            (source/MARKER).write_text(json.dumps(metadata, ensure_ascii=False), encoding='utf-8')
            self.disk.create(source, image, slot, password)
            _, restored, verified = self._read_profile(root, slot, password)
            if restored != manifest or not verified:
                raise AccountError('DMG 导出回读校验失败。')
            stage = None
            try:
                _safe_chain(target)
                descriptor, name = tempfile.mkstemp(prefix='.envscope-dmg-', suffix='.part', dir=target.parent)
                stage = Path(name)
                with os.fdopen(descriptor, 'wb') as out, image.open('rb') as inp:
                    shutil.copyfileobj(inp, out, CHUNK)
                    out.flush(); os.fsync(out.fileno())
                if _file_signature(stage) != _file_signature(image):
                    raise AccountError('DMG 导出文件校验失败。')
                # Publish the complete file atomically, without replacing an existing
                # destination. The stage is on the destination filesystem.
                _safe_chain(target)
                os.link(stage, target)
            finally:
                if stage is not None:
                    stage.unlink(missing_ok=True)
        return {'slot': slot, 'file': str(target), 'encrypted': True, 'verified': True, 'format': 'dmg',
                'verification': 'image_checksum_and_file_manifest', 'files': len(manifest)-1}

    def import_archive(self, filename, slot, password):
        if self.system != 'Darwin':
            raise AccountError('原版 DMG 兼容仅支持 macOS，请使用 .envsnap。')
        slot, password, source = _slot(slot), _password(password), _path(filename)
        # Cheap early refusal; AccountManager repeats this under its commit lock
        # after decryption, since the slot may change while a large image is read.
        with self.manager._lock():
            self.manager._require_clean(slot)
            if (self.manager.accounts_dir/slot).exists() or self.manager._read_current() == slot:
                raise AccountError('导入需要空的非活动槽位，现有资料未改动。')
        with self._workspace('import', slot) as root:
            _copy_image(source, root/'archive.dmg')
            profile, manifest, verified = self._read_profile(root, slot, password)
            self.manager.import_snapshot_from(profile, slot)
        return {'slot': slot, 'imported': True, 'encrypted': True, 'verified': True, 'format': 'dmg',
                'verification': 'image_checksum_and_file_manifest' if verified else 'legacy_image_checksum_and_copy_readback',
                'files': len(manifest)-1}
