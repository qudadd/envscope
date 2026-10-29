"""Streaming CSNAP001 interoperability, implemented from the format contract.

No vendor code is executed. Authenticate the complete encrypted input before
creating plaintext; validate ZIP metadata before extraction. AccountManager is
the only writer of account volumes and rechecks its lock and recovery state.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import unicodedata
import zipfile
import zlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .accounts import AccountError, _manifest, _safe_chain, _safe_entry, _RESERVED, validate_slot
from .snapshot_archive import CHUNK, FILES, LIMIT, _path, private_workspace

MAGIC = b'CSNAP001'
HEADER = 72
MARKER = '.claude-switcher-snapshot.json'
CENTRAL_LIMIT = 64 * 1024**2


def _password(value, exporting=False):
    try:
        units = len(value.encode('utf-16-le')) // 2 if isinstance(value, str) else 0
        if not (8 if exporting else 1) <= units <= 1024:
            raise ValueError
        return value.encode('utf-8')
    except (UnicodeError, ValueError):
        raise ValueError('.csnap 导出密码至少 8 个字符；导入使用原密码，最多 1024 个字符。') from None


def _slot(value):
    value = validate_slot(value)
    if value not in ('A', 'B', 'C', 'D'):
        raise AccountError('.csnap 仅支持 A–D，导入槽位须与原存档相同；其他槽位请使用 .envsnap。')
    return value


def _keys(password, salt):
    material = hashlib.pbkdf2_hmac('sha256', _password(password), salt, 200000, 64)
    return material[:32], material[32:]


def _signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _open_input(path, maximum):
    _safe_chain(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    stream = os.fdopen(descriptor, 'rb')
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        stream.close()
        raise AccountError('存档需为普通独立文件，且不能超过 8 GiB 上限。')
    return stream, info


def _copy(source, destination, maximum):
    stream, before = _open_input(source, maximum)
    with stream, destination.open('xb') as out:
        size = 0
        while chunk := stream.read(CHUNK):
            size += len(chunk)
            if size > maximum:
                raise AccountError('读取期间存档大小超限。')
            out.write(chunk)
        if size != before.st_size or _signature(os.fstat(stream.fileno())) != _signature(before):
            raise AccountError('读取期间文件发生变化，请重新导出后再试。')
        out.flush()
        os.fsync(out.fileno())
    destination.chmod(0o600)


def _encrypt(source, destination, password):
    stream, before = _open_input(source, LIMIT)
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(16)
    key, mac_key = _keys(password, salt)
    header = MAGIC + salt + iv
    mac = hmac.new(mac_key, header, 'sha256')
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(128).padder()
    with stream, destination.open('x+b') as out:
        out.write(header + bytes(32))
        count = 0
        while chunk := stream.read(CHUNK):
            count += len(chunk)
            if count > LIMIT:
                raise AccountError('存档超过 8 GiB 上限。')
            encrypted = encryptor.update(padder.update(chunk))
            out.write(encrypted)
            mac.update(encrypted)
        encrypted = encryptor.update(padder.finalize()) + encryptor.finalize()
        out.write(encrypted)
        mac.update(encrypted)
        if count != before.st_size or _signature(os.fstat(stream.fileno())) != _signature(before):
            raise AccountError('读取期间资料发生变化，导出已停止。')
        out.seek(40)
        out.write(mac.digest())
        out.flush()
        os.fsync(out.fileno())
    destination.chmod(0o600)


def _decrypt(source, destination, password):
    stream, before = _open_input(source, LIMIT + HEADER + 16)
    created = False
    try:
        with stream:
            header = stream.read(HEADER)
            size = before.st_size - HEADER
            if len(header) != HEADER or header[:8] != MAGIC or size < 16 or size % 16:
                raise AccountError('.csnap 文件头或长度无效，未导入资料。')
            key, mac_key = _keys(password, header[8:24])
            mac = hmac.new(mac_key, header[:40], 'sha256')
            remaining = size
            while remaining:
                chunk = stream.read(min(CHUNK, remaining))
                if not chunk:
                    raise AccountError('存档被截断，未导入资料。')
                mac.update(chunk)
                remaining -= len(chunk)
            if not hmac.compare_digest(mac.digest(), header[40:72]):
                raise AccountError('密码不正确或 .csnap 已损坏，未导入任何账号资料。')
            # Only authenticated input reaches plaintext creation. Recheck the
            # second read as well, so in-place mutations never reach extraction.
            stream.seek(HEADER)
            second_mac = hmac.new(mac_key, header[:40], 'sha256')
            decryptor = Cipher(algorithms.AES(key), modes.CBC(header[24:40])).decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            with destination.open('xb') as out:
                created = True
                remaining, total = size, 0
                while remaining:
                    chunk = stream.read(min(CHUNK, remaining))
                    if not chunk:
                        raise AccountError('存档被截断。')
                    remaining -= len(chunk)
                    second_mac.update(chunk)
                    plain = unpadder.update(decryptor.update(chunk))
                    total += len(plain)
                    if total > LIMIT:
                        raise AccountError('存档展开大小超限。')
                    out.write(plain)
                tail = unpadder.update(decryptor.finalize()) + unpadder.finalize()
                if (total + len(tail) > LIMIT or not hmac.compare_digest(second_mac.digest(), header[40:72])
                        or _signature(os.fstat(stream.fileno())) != _signature(before)):
                    raise AccountError('读取期间存档发生变化，未导入资料。')
                out.write(tail)
            destination.chmod(0o600)
    except Exception as exc:
        if created:
            destination.unlink()
        if isinstance(exc, ValueError):
            raise AccountError('密码不正确或 .csnap 已损坏，未导入任何账号资料。') from None
        raise


def _portable_path(name):
    parts = name.rstrip('/').split('/')
    reserved = _RESERVED | {'CONIN$', 'CONOUT$', *(prefix + n for prefix in ('COM', 'LPT') for n in '¹²³')}
    if (not name or name.startswith('/') or name.endswith('//') or len(name.encode('utf-8')) > 4096
            or any(not p or p in ('.', '..') or p.endswith((' ', '.')) or len(p.encode('utf-8')) > 255
                   or p.split('.')[0].upper() in reserved
                   or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in p) for p in parts)):
        raise AccountError('存档含不安全或不能在 Windows / macOS 使用的路径。')
    return parts


def _validate_names(entries):
    seen, spellings, kinds = set(), {}, {}
    for name, directory in entries:
        parts = _portable_path(name)
        canonical = '/'.join(unicodedata.normalize('NFC', part).casefold() for part in parts)
        if canonical in seen:
            raise AccountError('存档包含重复或大小写冲突的路径。')
        seen.add(canonical)
        kinds[canonical] = directory
        for n in range(1, len(parts) + 1):
            raw = '/'.join(parts[:n])
            key = unicodedata.normalize('NFC', raw).casefold()
            if key in spellings and spellings[key] != raw:
                raise AccountError('存档包含大小写或 Unicode 名称冲突。')
            spellings[key] = raw
    for name in kinds:
        parts = name.split('/')
        if any(kinds.get('/'.join(parts[:n])) is False for n in range(1, len(parts))):
            raise AccountError('存档的文件与目录路径冲突。')


def _profile_tree(root):
    _safe_chain(root)
    total, count, todo = 0, 0, [root]
    device = root.stat().st_dev
    names = []
    while todo:
        directory = todo.pop()
        for path in directory.iterdir():
            _safe_entry(path)
            info = path.lstat()
            name = path.relative_to(root).as_posix()
            if name.casefold() == MARKER.casefold():
                raise AccountError('账号含 .csnap 保留标记文件，请使用 .envsnap 以完整保留它。')
            count += 1
            if stat.S_ISDIR(info.st_mode) and info.st_dev == device:
                todo.append(path)
                names.append((name, True))
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_dev == device:
                total += info.st_size
                names.append((name, False))
            else:
                raise AccountError('账号包含链接、嵌套挂载或特殊文件，导出已停止。')
            if total > LIMIT or count > FILES:
                raise AccountError('资料超过 8 GiB 或 200000 项上限。')
    _validate_names(names)
    return _manifest(root)


def _pack(source, destination, slot):
    before = _profile_tree(source)
    metadata = {'format': 'claude-switcher-snapshot', 'version': 1, 'account': slot,
                'created': datetime.now(timezone.utc).isoformat(), 'platform': 'Windows'}
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED, strict_timestamps=False) as archive:
        archive.writestr(MARKER, json.dumps(metadata, ensure_ascii=False).encode('utf-8'))
        for name, entry in before.items():
            if name == '.':
                continue
            archive.write(source/name, name + '/' if entry[0] == 'directory' else name)
    if destination.stat().st_size > LIMIT or _profile_tree(source) != before:
        raise AccountError('资料超限或读取期间发生变化，导出已停止。')


def _zip_directory_guard(path):
    """Bound central directory memory before ZipFile reads it (including ZIP64)."""
    with path.open('rb') as stream:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - 65557))
        tail = stream.read()
        offset = tail.rfind(b'PK\x05\x06')
        if offset < 0 or len(tail) - offset < 22:
            raise AccountError('ZIP 尾部无效。')
        _, disk, cd_disk, disk_count, count, length, start, comment = struct.unpack('<4s4H2LH', tail[offset:offset+22])
        end = size - len(tail) + offset
        if disk or cd_disk or disk_count != count or offset + 22 + comment != len(tail):
            raise AccountError('不支持分卷或尾部异常的 ZIP。')
        if count == 0xffff or length == 0xffffffff or start == 0xffffffff:
            if end < 20:
                raise AccountError('ZIP64 尾部无效。')
            stream.seek(end - 20)
            sig, zip_disk, record, disks = struct.unpack('<4sLQL', stream.read(20))
            if sig != b'PK\x06\x07' or zip_disk or disks != 1 or record + 56 > end - 20:
                raise AccountError('ZIP64 索引无效。')
            stream.seek(record)
            header = stream.read(56)
            sig, length64, _, _, disk, cd_disk, disk_count, count, length, start = struct.unpack('<4sQ2H2L4Q', header)
            if (sig != b'PK\x06\x06' or length64 < 44 or record + 12 + length64 != end - 20
                    or disk or cd_disk or disk_count != count):
                raise AccountError('ZIP64 目录无效。')
            end = record
        if count > FILES + 1 or length > CENTRAL_LIMIT or start + length != end:
            raise AccountError('ZIP 文件数量、目录大小或偏移超限。')


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AccountError('存档元数据含重复字段。')
        result[key] = value
    return result


def _unpack(source, destination, slot):
    _zip_directory_guard(source)
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        if len(entries) > FILES + 1 or sum(i.file_size for i in entries) > LIMIT:
            raise AccountError('存档展开大小或文件数量超限。')
        _validate_names((item.filename, item.is_dir()) for item in entries)
        for item in entries:
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (item.orig_filename != item.filename or item.flag_bits & 1 or item.external_attr & 0x400
                    or kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or kind == stat.S_IFDIR and not item.is_dir() or kind == stat.S_IFREG and item.is_dir()
                    or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or item.is_dir() and item.file_size):
                raise AccountError('存档包含链接、特殊文件或不支持的压缩项。')
        marker = archive.getinfo(MARKER)
        if marker.is_dir() or marker.file_size > 16384:
            raise AccountError('存档元数据缺失或超过 16 KiB。')
        metadata = json.loads(archive.read(marker).decode('utf-8-sig'), object_pairs_hook=_unique_json)
        if (not isinstance(metadata, dict) or metadata.get('format') != 'claude-switcher-snapshot'
                or type(metadata.get('version')) is not int or metadata['version'] != 1
                or not isinstance(metadata.get('account'), str) or metadata['account'].upper() != slot):
            raise AccountError('.csnap 元数据无效或账号槽位不匹配，请选择存档原来的 A–D 槽位。')
        _safe_chain(destination)
        destination.mkdir(mode=0o700)
        for item in entries:
            if item.filename == MARKER:
                continue
            target = destination.joinpath(*_portable_path(item.filename))
            _safe_chain(target)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            total = 0
            with archive.open(item) as inp, target.open('xb') as out:
                while chunk := inp.read(CHUNK):
                    total += len(chunk)
                    if total > item.file_size:
                        raise AccountError('ZIP 实际内容大小与目录不符。')
                    out.write(chunk)
            if total != item.file_size:
                raise AccountError('ZIP 内容不完整。')
            target.chmod(0o600)


class CsnapArchive:
    def __init__(self, manager, work_root):
        self.manager, self.work_root = manager, Path(work_root).absolute()

    def export(self, slot, filename, password):
        slot = _slot(slot)
        _password(password, exporting=True)
        target = _path(filename)
        if target.suffix.lower() != '.csnap' or os.path.lexists(target) or not target.parent.is_dir():
            raise ValueError('请选择现有目录中的新 .csnap 文件，不覆盖已有文件。')
        for managed in (self.manager.state_dir, self.manager.data_dir, self.work_root):
            try:
                common = os.path.commonpath([os.path.normcase(str(managed)), os.path.normcase(str(target))])
            except ValueError:
                common = None
            if common in (os.path.normcase(str(managed)), os.path.normcase(str(target))):
                raise AccountError('请将加密文件保存在账号和暂存管理目录以外。')
        self.manager.archive_preflight(slot)
        stage = target.with_name(target.name + '.' + secrets.token_hex(8) + '.part')
        try:
            with private_workspace(self.work_root) as root:
                # Bound the source before AccountManager hashes/copies it.
                _profile_tree(self.manager.accounts_dir / slot)
                self.manager.copy_snapshot_to(slot, root/'profile')
                _pack(root/'profile', root/'payload.zip', slot)
                _encrypt(root/'payload.zip', stage, password)
                _decrypt(stage, root/'verified.zip', password)
                _unpack(root/'verified.zip', root/'verified', slot)
                if _manifest(root/'profile') != _manifest(root/'verified'):
                    raise AccountError('导出回读结果不一致，未生成备份。')
                # Same-volume exclusive publication: no partial target on crash,
                # and no replacement of a concurrently created destination.
                os.link(stage, target)
            return {'slot': slot, 'encrypted': True, 'format': 'csnap', 'destination': str(target),
                    'verified': True, 'verification': 'hmac_sha256_and_copy_readback'}
        finally:
            if stage.exists():
                stage.unlink()

    def import_archive(self, filename, slot, password):
        slot = _slot(slot)
        _password(password)
        source = _path(filename)
        if source.suffix.lower() != '.csnap':
            raise ValueError('请选择 .csnap 存档。')
        self.manager.archive_preflight(slot, importing=True)
        try:
            with private_workspace(self.work_root) as root:
                _copy(source, root/'encrypted.csnap', LIMIT + HEADER + 16)
                _decrypt(root/'encrypted.csnap', root/'payload.zip', password)
                _unpack(root/'payload.zip', root/'profile', slot)
                result = self.manager.import_snapshot_from(root/'profile', slot)
            return {**result, 'encrypted': True, 'format': 'csnap', 'verified': True,
                    'verification': 'hmac_sha256_and_copy_readback'}
        except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeError, struct.error,
                NotImplementedError, zlib.error, RecursionError):
            raise AccountError('.csnap 结构无效或内容损坏，未导入账号资料。') from None
