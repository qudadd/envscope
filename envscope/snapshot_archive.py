"""Authenticated, streaming account archives. Never export a live profile.

Format v1: magic(8), salt(16), nonce(12), plaintext length(8, big endian),
AES-256-GCM ciphertext, tag(16). The complete header is authenticated.
Scrypt parameters are fixed (N=2**15, r=8, p=1); no file controls KDF cost.
No ZIP entry is inspected or extracted before authentication completes.
"""
from contextlib import contextmanager
import csv
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import subprocess
import tempfile
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .accounts import AccountError, _manifest, _safe_chain, _RESERVED

MAGIC = b'ENVSNAP1'
HEADER = 44
LIMIT = 8 * 1024**3
FILES = 200000
CHUNK = 1024**2


@contextmanager
def private_workspace(parent):
    parent = Path(parent).absolute()
    _safe_chain(parent)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='work-', dir=parent) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        if os.name == 'nt':
            # Drop inherited access before placing any plaintext in the folder.
            options = dict(capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            result = subprocess.run(['whoami.exe', '/user', '/fo', 'csv', '/nh'], **options)
            try:
                sid = next(csv.reader(io.StringIO(result.stdout)))[1]
            except (IndexError, StopIteration):
                raise AccountError('无法确认当前用户，未创建明文暂存资料。') from None
            if result.returncode or not sid.startswith('S-1-') or not all(c in 'S-0123456789' for c in sid):
                raise AccountError('无法确认当前用户，未创建明文暂存资料。')
            result = subprocess.run(['icacls.exe', str(root), '/inheritance:r', '/grant:r', '*'+sid+':(OI)(CI)F'], **options)
            if result.returncode:
                raise AccountError('无法限制暂存目录权限，未导出资料。')
        yield root


def _password(value):
    if not isinstance(value, str) or not 12 <= len(value) <= 1024:
        raise ValueError('加密密码需为 12–1024 个字符，请单独保管。')
    return value.encode('utf-8')


def _key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(_password(password))


def _path(value):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError('请选择绝对路径。')
    path = Path(value)
    _safe_chain(path)
    return path


def _encrypt(source, destination, password):
    size = source.stat().st_size
    if size > LIMIT:
        raise AccountError('存档超过本版 8 GiB 上限。')
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = MAGIC + salt + nonce + size.to_bytes(8, 'big')
    cipher = Cipher(algorithms.AES(_key(password, salt)), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    with source.open('rb') as inp, destination.open('xb') as out:
        out.write(header)
        for chunk in iter(lambda: inp.read(CHUNK), b''):
            out.write(cipher.update(chunk))
        out.write(cipher.finalize())
        out.write(cipher.tag)
        out.flush()
        os.fsync(out.fileno())


def _decrypt(source, destination, password):
    _safe_chain(source)
    if not source.is_file() or not HEADER+16 <= source.stat().st_size <= LIMIT+HEADER+16:
        raise AccountError('不是有效的 EnvScope 加密存档，或超过 8 GiB 上限。')
    with source.open('rb') as inp:
        header = inp.read(HEADER)
        size = int.from_bytes(header[36:44], 'big')
        if header[:8] != MAGIC or size > LIMIT or source.stat().st_size != size+HEADER+16:
            raise AccountError('存档头或长度不完整，未导入资料。')
        cipher = Cipher(algorithms.AES(_key(password, header[8:24])), modes.GCM(header[24:36])).decryptor()
        cipher.authenticate_additional_data(header)
        with destination.open('xb') as out:
            remaining = size
            while remaining:
                chunk = inp.read(min(CHUNK, remaining))
                if not chunk:
                    raise AccountError('存档被截断。')
                remaining -= len(chunk)
                out.write(cipher.update(chunk))
            try:
                out.write(cipher.finalize_with_tag(inp.read(16)))
            except InvalidTag:
                raise AccountError('密码不正确或存档已损坏，未导入任何账号资料。') from None


def _pack(source, archive):
    manifest = _manifest(source)
    if len(manifest) > FILES or sum(v[1] for v in manifest.values() if v[0] == 'file') > LIMIT:
        raise AccountError('资料超过存档大小或文件数量上限。')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_STORED) as z:
        z.writestr('manifest.json', json.dumps({'format':1, 'files':manifest}, ensure_ascii=False))
        for name, info in manifest.items():
            if name == '.':
                continue
            if info[0] == 'directory':
                z.writestr('data/'+name+'/', b'')
            else:
                z.write(source / name, 'data/'+name)
    if _manifest(source) != manifest:
        raise AccountError('读取期间资料发生变化，导出已停止。')


def _unpack(archive, destination):
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > FILES+1 or sum(i.file_size for i in entries) > LIMIT:
            raise AccountError('存档展开大小或文件数量超限。')
        seen = set()
        for item in entries:
            path = PurePosixPath(item.filename)
            parts = path.parts
            mode = item.external_attr >> 16
            raw_parts = item.filename.rstrip('/').split('/')
            if (item.orig_filename != item.filename or not parts or path.is_absolute() or '\\' in item.filename or '\x00' in item.filename
                    or any(not p or p in ('.', '..') or ':' in p or p.endswith((' ', '.')) or p.split('.')[0].upper() in _RESERVED for p in raw_parts)
                    or stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR) or item.compress_type != zipfile.ZIP_STORED
                    or item.filename.rstrip('/').casefold() in seen
                    or item.filename != 'manifest.json' and (len(parts)<2 or parts[0]!='data')):
                raise AccountError('存档包含不安全、重复或不支持的文件项。')
            seen.add(item.filename.rstrip('/').casefold())
        if z.getinfo('manifest.json').file_size > 32 * 1024**2:
            raise AccountError('存档清单超限。')
        metadata = json.loads(z.read('manifest.json'))
        if not isinstance(metadata, dict) or metadata.get('format') != 1 or not isinstance(metadata.get('files'), dict):
            raise AccountError('存档清单无效。')
        destination.mkdir(mode=0o700)
        for item in entries:
            if item.filename == 'manifest.json':
                continue
            target = destination.joinpath(*PurePosixPath(item.filename).parts[1:])
            _safe_chain(target)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with z.open(item) as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out, CHUNK)
                target.chmod(0o600)
        actual = {k:list(v) for k,v in _manifest(destination).items()}
        if actual != metadata['files']:
            raise AccountError('文件校验与存档清单不一致，未导入资料。')


class SnapshotArchive:
    def __init__(self, manager, work_root):
        self.manager, self.work_root = manager, Path(work_root)

    def export(self, slot, filename, password):
        _password(password)
        target = _path(filename)
        if target.suffix != '.envsnap' or target.exists() or not target.parent.is_dir():
            raise ValueError('导出需为现有目录中的新 .envsnap 文件，不覆盖已有文件。')
        # A destination in a live/profile tree could be lost on an account swap.
        for managed in (self.manager.state_dir, self.manager.data_dir):
            if target == managed or managed in target.parents:
                raise AccountError('请将加密文件保存在账号管理目录以外。')
        stage = target.with_name(target.name+'.'+secrets.token_hex(8)+'.part')
        try:
            with private_workspace(self.work_root) as root:
                profile, archive = root/'profile', root/'payload.zip'
                self.manager.copy_snapshot_to(slot, profile)
                _pack(profile, archive)
                _encrypt(archive, stage, password)
                _decrypt(stage, root/'verified.zip', password)
                _unpack(root/'verified.zip', root/'verified-profile')
                # Exclusive creation cannot clobber a concurrent file.
                with stage.open('rb') as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out, CHUNK)
                    out.flush(); os.fsync(out.fileno())
            return {'slot':slot, 'encrypted':True, 'destination':str(target), 'verified':True}
        finally:
            if stage.exists():
                stage.unlink()

    def import_archive(self, filename, slot, password):
        _password(password)
        source = _path(filename)
        try:
            with private_workspace(self.work_root) as root:
                _decrypt(source, root/'payload.zip', password)
                _unpack(root/'payload.zip', root/'profile')
                result = self.manager.import_snapshot_from(root/'profile', slot)
            return {**result, 'encrypted':True, 'verified':True}
        except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeError):
            raise AccountError('存档结构无效，未导入资料。') from None
