"""Bounded, opt-out command metadata and a strict diagnostic ZIP allowlist.

Free text, exception messages, arguments, paths and raw reports are never log
fields. Export reconstructs every entry; even a poisoned local log is not copied.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import hashlib
from io import BytesIO
import json
import math
import os
from pathlib import Path
import platform
import stat
import tempfile
import threading
import time
from zipfile import ZipFile, ZIP_DEFLATED

from . import __version__, __release__
from .accounts import _safe_chain

LIMIT = 512 * 1024
FILES = ('commands.1.jsonl', 'commands.jsonl')
STATUSES = frozenset(('completed', 'failed', 'blocked', 'planned', 'enabled', 'disabled',
                      'confirmation_required', 'retest_required', 'unavailable', 'cancelled', 'returned'))
COMMANDS = frozenset(('audit', 'maintenance-audit', 'check-config-save', 'settings-save', 'settings-restore',
                      'environment-confirm', 'support-bundle', 'diagnostics-export', 'diagnostics-clear',
                      'account-switch', 'account-add', 'account-label', 'app-launch', 'app-restart', 'open-safe',
                      'archive-export', 'archive-import', 'snapshot-export', 'snapshot-import',
                      'solution-apply', 'solution-undo', 'inspection-apply', 'region-apply', 'region-undo',
                      'client-apply', 'client-restore', 'routing-apply', 'routing-undo',
                      'system-network-apply', 'system-network-restore', 'language-apply', 'language-restore',
                      'components-apply', 'guard-enable', 'guard-disable', 'maintenance-enable', 'maintenance-disable',
                      'maintenance-run', 'timezone-service-apply', 'proxy-diagnose', 'cli-info', 'fingerprint', 'other'))
COUNTS = ('pass', 'fail', 'warn', 'unknown', 'skipped')
_mutex = threading.RLock()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def _safe_entry(value):
    if not isinstance(value, dict): return None
    try:
        at = datetime.fromisoformat(value['at'])
        duration = value['duration_ms']
        if (at.tzinfo is None or value.get('command') not in COMMANDS or value.get('state') not in STATUSES
                or type(duration) is not int or not 0 <= duration <= 86400000): return None
        return {'at': at.astimezone(timezone.utc).isoformat(timespec='seconds'),
                'command': value['command'], 'state': value['state'], 'duration_ms': duration}
    except (KeyError, TypeError, ValueError, OverflowError): return None


def _read_file(path):
    _safe_chain(path)
    if not path.exists(): return b''
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
            raise ValueError('诊断日志超出限制或不是独立常规文件')
        return stream.read(LIMIT + 1)


class DiagnosticLog:
    def __init__(self, store):
        self.store = store
        self.root = store.root / 'diagnostics'
        self.memory = []
        self.last_error = False

    def safe_record(self, command, state, elapsed=0):
        try:
            result = self.record(command, state, elapsed)
            self.last_error = False
            return result
        except (ValueError, OSError, RuntimeError):
            self.last_error = True
            return False

    def enabled(self):
        from .check_preferences import validate
        if not self.store.memory:
            path=self.store.root/'settings.private.json'
            _safe_chain(path)
            if path.exists():
                raw=self.store._read('settings.private.json',None)
                if not isinstance(raw,dict): raise ValueError('检测偏好无法读取，未假定日志同意')
                return validate(raw.get('check_config',{}))['logging']
        return validate(self.store.settings().get('check_config',{}))['logging']

    @contextmanager
    def lock(self, create=True):
        with _mutex:
            if self.store.memory:
                yield
                return
            _safe_chain(self.root)
            if create:self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = self.root / '.commands.lock'
            _safe_chain(path)
            flags = os.O_RDWR | os.O_CREAT if create else os.O_RDONLY
            fd = os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
            with os.fdopen(fd, 'r+b' if create else 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1:
                    raise ValueError('诊断锁文件无法核对')
                if not info.st_size:
                    if not create:raise ValueError('诊断锁尚未完整写入，读取未创建文件')
                    stream.write(b'0'); stream.flush()
                for attempt in range(20):
                    stream.seek(0)
                    try:
                        if os.name == 'nt':
                            import msvcrt
                            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK if create else msvcrt.LK_NBRLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(stream.fileno(), (fcntl.LOCK_EX if create else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if attempt == 19: raise ValueError('诊断日志正被另一进程使用') from None
                        time.sleep(.05)
                try: yield
                finally:
                    stream.seek(0)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def record(self, command, state, elapsed=0):
        """Logging failure is visible in status, never a retry of the operation."""
        if not self.enabled(): return False
        elapsed = elapsed if type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0 else 0
        entry = {'at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                 'command': command if isinstance(command, str) and command in COMMANDS else 'other',
                 'state': state if isinstance(state, str) and state in STATUSES else 'returned',
                 'duration_ms': min(86400000, round(elapsed * 1000))}
        data = encoded(entry)
        with self.lock():
            if self.store.memory:
                self.memory = (self.memory + [entry])[-4096:]
                return True
            current, old = self.root / FILES[1], self.root / FILES[0]
            raw = _read_file(current)
            _read_file(old)  # Refuse a linked, oversized or special rotation target.
            if len(raw) + len(data) > LIMIT:
                os.replace(current, old)
            _safe_chain(current)
            fd = os.open(current, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
            with os.fdopen(fd, 'ab') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise ValueError('诊断日志路径不安全')
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return True

    def entries(self):
        if not self.enabled(): return []
        # A read never creates the log directory or a lock file.
        if not self.store.memory and not self.root.exists(): return []
        with self.lock(create=False):
            if self.store.memory: return [e for v in self.memory if (e := _safe_entry(v))]
            result = []
            for name in FILES:
                for line in _read_file(self.root / name).splitlines():
                    try: entry = _safe_entry(json.loads(line))
                    except (ValueError, TypeError, RecursionError): entry = None
                    if entry: result.append(entry)
            return result

    def clear(self, confirmed=False):
        if confirmed is not True: return {'state': 'confirmation_required', 'reason': '仅清除两份命令诊断日志；检测历史、修复备份与守护留痕保留。'}
        if self.store.memory: self.memory = []
        elif self.root.exists():
            with self.lock():
                for name in FILES:
                    path=self.root/name;_safe_chain(path)
                    if path.exists():
                        info=path.stat()
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: raise ValueError('诊断日志不是独立常规文件，未删除')
                for name in FILES: (self.root / name).unlink(missing_ok=True)
        self.last_error=False
        return {'state': 'completed', 'reason': '命令诊断日志已清除。检测历史、修复备份与守护留痕仍保留。'}

    def status(self):
        enabled = False
        try:
            enabled = self.enabled()
            if self.last_error: raise ValueError('last write failed')
            entries = self.entries()
            return {'enabled': enabled, 'state': 'ready' if enabled else 'disabled', 'entries': len(entries),
                    'limit_bytes': LIMIT, 'retained_files': 2}
        except (ValueError, OSError):
            return {'enabled': enabled, 'state': 'unavailable', 'entries': None,
                    'reason': '诊断日志或同意设置无法读取；未复制未知文件或将日志失败当作操作失败。'}

    def summary(self, report=None):
        from .check_catalog import check_catalog
        from .check_preferences import validate
        from .legacy import UPSTREAM_COMMIT, UPSTREAM_REPOSITORY
        known = {row['id']: row['title'] for row in check_catalog()}
        settings = self.store.settings()
        rows = []
        if isinstance(report, dict) and isinstance(report.get('findings'), list):
            seen = set()
            for finding in report['findings'][:256]:
                if not isinstance(finding, dict): continue
                key, status = finding.get('id'), finding.get('status')
                if isinstance(key, str) and key in known and key not in seen and status in COUNTS:
                    rows.append({'id': key, 'title': known[key], 'status': status}); seen.add(key)
        return {'schema_version': 1, 'tool': 'envscope', 'version': __version__, 'release': __release__,
                'contains_sensitive': False, 'raw_report_included': False,
                'system': platform.system() if platform.system() in ('Windows', 'Darwin') else 'other',
                'check_config': validate(settings.get('check_config', {})), 'log': self.status(),
                'checks': rows, 'counts': {key: sum(r['status'] == key for r in rows) for key in COUNTS},
                'upstream': {'repository': UPSTREAM_REPOSITORY, 'vendored_commit': UPSTREAM_COMMIT},
                'scope': '只包含固定检查名称和状态、检测偏好及命令元数据；没有原始报告、地址、路径、账号、配置、异常原文或身份资料。',
                'report_scope': '本次提供的检查状态快照；不证明当前环境或实际登录可用。' if rows else '尚无检测报告。'}

    def archive(self, report=None):
        summary = self.summary(report)
        try: entries = self.entries()
        except (ValueError, OSError): entries = []
        stream = BytesIO()
        with ZipFile(stream, 'w', ZIP_DEFLATED) as archive:
            archive.writestr('summary.json', encoded(summary))
            archive.writestr('commands.jsonl', b''.join(encoded(e) for e in entries))
            archive.writestr('README.txt', ('EnvScope 脱敏诊断包\n' + summary['scope'] + '\n'
                              '命令耗时与时间仍可能透露使用习惯；分享前请自行复核。日志关闭时不会导出旧日志。\n').encode('utf-8'))
        data = stream.getvalue()
        return {'filename': 'EnvScope-diagnostics-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '.zip',
                'format': 'zip', 'data': base64.b64encode(data).decode('ascii'),
                'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def write_archive(path, archive):
    """A native save dialog selected the destination; replace only a stable file."""
    path = Path(path)
    if not path.is_absolute() or path.suffix.lower() != '.zip': raise ValueError('请选择绝对路径的 ZIP 文件')
    _safe_chain(path)
    if not path.parent.is_dir(): raise ValueError('导出目录不存在')
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1): raise ValueError('导出目标不是独立常规文件')
    previous = path.read_bytes() if path.exists() and path.stat().st_size <= 16 * 1024**2 else None
    if path.exists() and previous is None: raise ValueError('已有文件超出覆盖核对范围')
    data = base64.b64decode(archive['data'], validate=True)
    if len(data) != archive['size'] or hashlib.sha256(data).hexdigest() != archive['sha256']:
        raise ValueError('诊断 ZIP 内容与摘要不符，未写入')
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.envscope-diagnostics-', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    try:
        _safe_chain(path)
        if path.exists() and path.read_bytes() != previous or not path.exists() and previous is not None:
            raise ValueError('导出位置在选择后已改变，未覆盖')
        os.replace(temporary, path)
        if path.read_bytes() != data: raise ValueError('诊断包写入后校验失败')
    finally: temporary.unlink(missing_ok=True)
    return {'state': 'completed', 'reason': '脱敏 ZIP 已导出；分享前请复核时间与命令记录。',
            'file': str(path), 'sha256': archive['sha256'], 'size': len(data)}
