"""Explicit account operations with verified copies and recoverable commits.

The legacy ``accounts/<slot>`` directories remain plain profile snapshots. Labels
live separately in ``account-labels.json``. Construction and listing do not write
anything. This module never discovers, stops, or starts a real process itself;
the action caller supplies process callbacks and a successful preflight.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import time
import uuid

from .profile_copy import copy_profile_file


class AccountError(RuntimeError):
    """A requested account action could not safely complete."""


class PreflightError(AccountError):
    """The caller did not provide an affirmative, fresh preflight."""


class RecoveryRequired(AccountError):
    """An incomplete or ambiguous state must be reviewed before writing."""


_SLOT = re.compile(r"[A-Za-z0-9_-]{1,32}\Z", re.ASCII)
_RESERVED = {"CON", "PRN", "AUX", "NUL", *("COM" + str(i) for i in range(1, 10)),
             *("LPT" + str(i) for i in range(1, 10))}


def validate_slot(slot):
    if not isinstance(slot, str) or not _SLOT.fullmatch(slot) or slot.upper() in _RESERVED:
        raise AccountError("Slot must use 1-32 ASCII letters, digits, underscores or hyphens; reserved device names are forbidden.")
    return slot.upper() if slot.upper() in {"A", "B", "C", "D"} else slot


def _redirect(path):
    info = path.lstat()
    return (stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0) & 0x400)
            or bool(getattr(info, "st_reparse_tag", 0)))


def _safe_entry(path):
    if os.path.lexists(path) and _redirect(path):
        raise AccountError("Symlinks and reparse points are forbidden in account paths.")


def _safe_chain(path):
    for candidate in (path, *path.parents):
        _safe_entry(candidate)


def _file_signature(path):
    _safe_entry(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AccountError("A profile entry changed while being read.")
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return ("file", info.st_size, hasher.hexdigest())


def _manifest(root, hashes=True):
    """Inspect every entry without following directory links or special files."""
    _safe_entry(root)
    if not root.is_dir():
        raise AccountError("Expected a profile directory.")
    result = {".": ("directory",)}
    todo = [root]
    while todo:
        directory = todo.pop()
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        for entry in children:
            path = Path(entry.path)
            _safe_entry(path)
            info = path.lstat()
            key = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                result[key] = ("directory",)
                todo.append(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise AccountError("Shared hard-linked files are forbidden in isolated account profiles.")
                result[key] = _file_signature(path) if hashes else ("file", info.st_size, None)
            else:
                raise AccountError("Special files are forbidden in profile snapshots.")
    return result


def _copy_verified(source, destination):
    try:
        common = os.path.commonpath([os.path.normcase(str(source)), os.path.normcase(str(destination))])
    except ValueError:  # Separate Windows drives are a supported copy case.
        common = None
    if common in {os.path.normcase(str(source)), os.path.normcase(str(destination))}:
        raise AccountError("Copy source and destination must not overlap.")
    _safe_chain(source)
    _safe_chain(destination)
    before = _manifest(source)
    if os.path.lexists(destination):
        raise RecoveryRequired("A staging directory already exists; it was preserved.")
    shutil.copytree(source, destination, copy_function=copy_profile_file, symlinks=True)
    if before != _manifest(source) or before != _manifest(destination):
        raise AccountError("Snapshot verification failed or its source changed during copying.")
    destination.chmod(0o700)


def _tree_digest(path):
    _safe_chain(path)
    if not os.path.lexists(path):
        return None
    return hashlib.sha256(json.dumps(_manifest(path), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _remove_staging(path):
    if not os.path.lexists(path):
        return
    _manifest(path, hashes=False)
    shutil.rmtree(path)


def _atomic_text(path, text):
    _safe_entry(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class AccountManager:
    def __init__(self, state_dir, data_dir, current_filename=None, stop_app=None, launch_app=None, force_stop_app=None):
        self.state_dir = Path(os.path.abspath(os.fspath(state_dir)))
        self.data_dir = Path(os.path.abspath(os.fspath(data_dir)))
        self.accounts_dir = self.state_dir / "accounts"
        self.current_filename = current_filename or ("current.txt" if os.name == "nt" else "current")
        if self.current_filename not in {"current", "current.txt"}:
            raise AccountError("current_filename must be current or current.txt.")
        # The profile and account storage must not contain one another.
        state = os.path.normcase(str(self.state_dir))
        data = os.path.normcase(str(self.data_dir))
        try:
            common = os.path.commonpath([state, data])
        except ValueError:
            common = None
        if common in {state, data}:
            raise AccountError("Account storage and live profile paths must not overlap.")
        self.stop_app = stop_app
        self.force_stop_app = force_stop_app
        self.launch_app = launch_app
        self.labels_file = self.state_dir / "account-labels.json"
        self.journal_file = self.state_dir / "account-transaction.json"
        self.keep_file = self.state_dir / "keep-in-workspace.txt"
        from .account_recovery import AccountRecovery
        self.recovery = AccountRecovery(self)

    def _check_roots(self):
        for path in (self.accounts_dir, self.data_dir, self.labels_file, self.journal_file, self.keep_file):
            _safe_chain(path)
        for path in (self.state_dir, self.accounts_dir, self.data_dir):
            if path.exists() and not path.is_dir():
                raise AccountError("An account directory path is occupied by a file.")

    def _current_paths(self):
        primary = self.state_dir / self.current_filename
        other = self.state_dir / ("current" if self.current_filename == "current.txt" else "current.txt")
        return primary, other

    def _read_current(self):
        values = []
        for path in self._current_paths():
            _safe_entry(path)
            if path.exists():
                if not path.is_file() or path.stat().st_size > 256:
                    raise RecoveryRequired("Invalid legacy current-account marker.")
                value = path.read_text(encoding="utf-8-sig").strip()
                values.append(None if value in {"", "none"} else validate_slot(value))
        if len(set(values)) > 1:
            raise RecoveryRequired("current and current.txt disagree; neither was overwritten.")
        return values[0] if values else None

    def _labels(self):
        _safe_entry(self.labels_file)
        if not self.labels_file.exists():
            return {}
        try:
            if self.labels_file.stat().st_size > 65536:
                raise ValueError("oversized metadata")
            payload = json.loads(self.labels_file.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("labels"), dict):
                raise ValueError("invalid metadata")
            labels = payload["labels"]
            for slot, label in labels.items():
                if validate_slot(slot) != slot or not isinstance(label, str) or len(label) > 80 or any(ord(c) < 32 for c in label):
                    raise ValueError("invalid label")
            return labels
        except (ValueError, TypeError, OSError) as exc:
            raise RecoveryRequired("Account-label metadata is invalid; it was preserved.") from exc

    def _pending(self):
        pending = []
        if os.path.lexists(self.journal_file):
            pending.append("account-transaction.json")
        if os.path.lexists(self.state_dir / "keep-stage"):
            pending.append("keep-stage")
        if self.accounts_dir.exists():
            for child in self.accounts_dir.iterdir():
                if child.name.endswith((".new", ".previous")):
                    pending.append("accounts/" + child.name)
        for path in (self.data_dir.with_name(self.data_dir.name + ".new"),
                     self.data_dir.with_name(self.data_dir.name + ".previous")):
            if os.path.lexists(path):
                pending.append("profile/" + path.name)
        return sorted(pending)

    def _slots(self, labels=None):
        slots = {"A", "B", "C", "D"}
        slots.update((labels if labels is not None else self._labels()))
        current = self._read_current()
        if current:
            slots.add(current)
        if self.accounts_dir.exists():
            for path in self.accounts_dir.iterdir():
                if _SLOT.fullmatch(path.name):
                    slot = validate_slot(path.name)
                    if slot != path.name:
                        raise RecoveryRequired("Legacy slot casing is ambiguous; it was preserved.")
                    _safe_entry(path)
                    if not path.is_dir():
                        raise RecoveryRequired("A snapshot slot is occupied by a file.")
                    slots.add(slot)
        folded = {}
        for slot in slots:
            if slot.casefold() in folded and folded[slot.casefold()] != slot:
                raise RecoveryRequired("Slot names differ only by case and are not portable.")
            folded[slot.casefold()] = slot
        return sorted(slots, key=lambda slot: (slot not in {"A", "B", "C", "D"}, slot.casefold()))

    def list_accounts(self):
        self._check_roots()
        current = self._read_current()
        labels = self._labels()
        pending = self._pending()
        accounts = []
        for slot in self._slots(labels):
            snapshot = self.accounts_dir / slot
            has_snapshot = snapshot.is_dir()
            size = None
            modified = None
            if has_snapshot:
                manifest = _manifest(snapshot, hashes=False)
                size = sum(item[1] for item in manifest.values() if item[0] == "file")
                modified = datetime.fromtimestamp(snapshot.stat().st_mtime, timezone.utc).isoformat()
            accounts.append({"slot": slot, "label": labels.get(slot, ""), "has_snapshot": has_snapshot,
                             "is_current": slot == current, "bytes": size, "updated_at": modified,
                             "state": "recovery_required" if pending else "active" if slot == current else "archived" if has_snapshot else "empty"})
        return {"current": current, "accounts": accounts, "pending": pending,
                "recovery": self.recovery.status()}

    def inspect_integrity(self):
        """Read structural metadata without walking or hashing profile contents."""
        self._check_roots()
        current = self._read_current()
        labels = self._labels()
        slots = self._slots(labels)
        present = self.data_dir.is_dir()
        return {"valid": current is None or present, "tracked": current is not None, "live_profile_present": present,
                "slot_count": len(slots), "pending": self._pending()}

    @contextmanager
    def _lock(self):
        self._check_roots()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.accounts_dir.mkdir(exist_ok=True, mode=0o700)
        lock_path = self.state_dir / ".accounts.lock"
        _safe_entry(lock_path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        stream = os.fdopen(descriptor, "r+b")
        acquired = False
        try:
            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as exc:
                raise AccountError("Another account operation is in progress.") from exc
            self._check_roots()
            yield
        finally:
            if acquired:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()

    def _require_clean(self, slot=None):
        self._check_roots()
        if self._pending():
            raise RecoveryRequired("Incomplete .new/.previous state or transaction journal exists; all copies were preserved.")
        slots = self._slots()
        if slot and any(existing.casefold() == slot.casefold() and existing != slot for existing in slots):
            raise AccountError("Use the existing slot's exact letter case.")

    def rename_label(self, slot, label):
        slot = validate_slot(slot)
        if not isinstance(label, str) or len(label) > 80 or any(ord(c) < 32 for c in label):
            raise AccountError("Label must be at most 80 characters without control characters.")
        with self._lock():
            self._require_clean(slot)
            labels = self._labels()
            if label.strip():
                labels[slot] = label.strip()
            else:
                labels.pop(slot, None)
            encoded = json.dumps({"schema_version": 1, "labels": labels}, ensure_ascii=False, indent=2) + "\n"
            if len(encoded.encode("utf-8")) > 65536:
                raise AccountError("Account-label metadata is full.")
            _atomic_text(self.labels_file, encoded)
        return {"slot": slot, "label": label.strip()}

    def _write_current(self, slot, originals):
        # Update both markers only if both already existed, avoiding split state.
        primary, _ = self._current_paths()
        paths = list(originals) or [primary]
        if primary not in paths:
            paths.append(primary)
        for path in paths:
            _atomic_text(path, slot + "\n")


    def _keep_paths(self):
        if not self.keep_file.exists():
            return []
        if not self.keep_file.is_file() or self.keep_file.stat().st_size > 65536:
            raise AccountError("The optional retention list is invalid or too large.")
        paths = []
        for line in self.keep_file.read_text(encoding="utf-8-sig").splitlines():
            value = line.strip().replace("\\", "/")
            if not value or value.startswith("#"):
                continue
            while value.startswith("./"):
                value = value[2:]
            parts = value.rstrip("/").split("/")
            if (not value or len(value) > 1024 or PurePosixPath(value).is_absolute()
                    or any(part in {"", ".", ".."} for part in parts)
                    or ":" in value or any(ord(c) < 32 for c in value)):
                raise AccountError("Retention entries must be safe relative profile paths.")
            relative = Path(*parts)
            # An upstream retention file must never merge authentication or
            # local identity state into another account's complete profile.
            if parts[0].lower() != 'skills':
                raise AccountError('账号隔离禁止跨账号保留身份、Cookie、凭据或设置；keep-in-workspace.txt 仅允许 skills/ 下的通用技能文件。请调整清单后重试。')
            if relative not in paths:
                paths.append(relative)
        return paths

    def _merge_retained(self, live_stage, paths):
        # Both trees have been checked; only the disposable target stage changes.
        for relative in paths:
            source, destination = self.data_dir / relative, live_stage / relative
            _safe_chain(source)
            if not source.exists():
                continue
            _safe_chain(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                before = _manifest(source)
                if destination.exists() and not destination.is_dir():
                    destination.unlink()
                shutil.copytree(source, destination, copy_function=shutil.copy2,
                                symlinks=True, dirs_exist_ok=True)
                after = _manifest(destination)
                if before != _manifest(source) or any(after.get(key) != item for key, item in before.items()):
                    raise AccountError("Retained directory verification failed.")
            else:
                before = _file_signature(source)
                if destination.is_dir():
                    _remove_staging(destination)
                shutil.copy2(source, destination, follow_symlinks=False)
                if before != _file_signature(source) or before != _file_signature(destination):
                    raise AccountError("Retained file verification failed.")
        _manifest(live_stage, hashes=False)

    def _launch(self, result, preflight, checked_at):
        result["launched"] = False
        result["warnings"] = []
        if self.launch_app is not None:
            try:
                # Large profiles can take minutes to copy. Keep the committed
                # profile, but never launch on the initial, now-old measurement.
                if time.monotonic() - checked_at >= 45 and preflight() is not True:
                    result["warnings"].append("Profile is ready, but renewed preflight did not pass; the application was not launched.")
                    return result
                if self.launch_app() is False:
                    raise AccountError("Launch callback did not confirm success.")
                result["launched"] = True
            except Exception:
                result["warnings"].append("Profile is ready, but the application could not be launched.")
        return result

    def launch_checked(self, preflight, launch_app, restart=False, stop_app=None):
        """Launch without adopting or exchanging profiles, under the account lock."""
        if type(restart) is not bool or not callable(launch_app) or restart and not callable(stop_app):
            raise AccountError("Explicit process callbacks are required.")
        if not callable(preflight):
            raise PreflightError("A fresh preflight is required.")

        def check():
            try:
                ready = preflight()
            except Exception as exc:
                raise PreflightError("Desktop preflight did not complete.") from exc
            if ready is not True:
                raise PreflightError("Desktop preflight did not pass; no launch was requested.")

        check()
        with self._lock():
            self._require_clean()
            if self._read_current() is not None and not self.data_dir.is_dir():
                raise RecoveryRequired("The tracked live profile is missing; restore it before launching.")
            if restart:
                if stop_app() is not True:
                    return {"launched": False, "stop_confirmed": False, "profiles_changed": False}
                # Exit may take time or the network may change while it closes.
                check()
                self._require_clean()
                if self._read_current() is not None and not self.data_dir.is_dir():
                    raise RecoveryRequired("The tracked live profile is missing after exit.")
            launched = launch_app() is True
            return {"launched": launched, "stop_confirmed": True if restart else None, "profiles_changed": False}

    def switch(self, slot, preflight, allow_force=False):
        slot = validate_slot(slot)
        if type(allow_force) is not bool:
            raise AccountError('强制退出选项必须明确选择。')
        if not callable(preflight):
            raise PreflightError("A preflight callback is required.")
        try:
            ready = preflight()
        except Exception as exc:
            raise PreflightError("Preflight failed; no application was stopped or profile changed.") from exc
        if ready is not True:
            raise PreflightError("Preflight did not pass; no application was stopped or profile changed.")
        checked_at = time.monotonic()
        with self._lock():
            self._require_clean(slot)
            current = self._read_current()
            if current == slot and self.data_dir.exists():
                _manifest(self.data_dir, hashes=False)
                return self._launch({"slot": slot, "previous": current, "changed": False}, preflight, checked_at)
            if not callable(self.stop_app):
                raise AccountError("A process-stop callback is required before exchanging profiles.")
            if self.data_dir.exists():
                _manifest(self.data_dir, hashes=False)
            target = self.accounts_dir / slot
            if target.exists():
                _manifest(target, hashes=False)
            keep_paths = self._keep_paths()
            original_current = current
            live_exists = self.data_dir.exists()
            adopt = current is None and live_exists and any(self.data_dir.iterdir())
            if adopt:
                current = "A"
                if (self.accounts_dir / current).exists():
                    raise RecoveryRequired("Untracked live data and an A snapshot both exist; neither was overwritten.")
            elif current and not live_exists:
                # Restoring the same archived account is a safe recovery path.
                if current != slot or not target.exists():
                    raise RecoveryRequired("The current live profile is missing; restore its existing snapshot first.")
            from .event_log import append_event
            transaction=uuid.uuid4().hex
            def record(phase):
                append_event(self.state_dir/'account-events',{'at':datetime.now(timezone.utc).isoformat(),'kind':'account_exchange',
                             'transaction':transaction,'phase':phase,'previous':original_current,'slot':slot})
            record('requested')
            try:
                stopped = self.stop_app()
            except Exception as exc:
                record('exit_failed')
                raise AccountError("Application termination failed; profile data was preserved.") from exc
            if stopped is not True:
                if allow_force and callable(self.force_stop_app):
                    record('forced_exit_approved')
                    try:
                        stopped = self.force_stop_app()
                    except Exception:
                        stopped = False
                if stopped is not True:
                    record('exit_unconfirmed')
                    raise AccountError('Claude 退出未确认，资料没有交换。请保存工作并从 Claude 托盘菜单退出后重试；也可单独选择允许强制退出。')
            live_stage = self.data_dir.with_name(self.data_dir.name + ".new")
            live_previous = self.data_dir.with_name(self.data_dir.name + ".previous")
            archive = self.accounts_dir / current if current and live_exists else None
            archive_stage = archive.with_name(archive.name + ".new") if archive else None
            archive_previous = archive.with_name(archive.name + ".previous") if archive else None
            originals = {path: path.read_text(encoding="utf-8-sig") for path in self._current_paths() if path.exists()}
            archive_old_moved = archive_committed = live_old_moved = live_committed = False
            committed = False
            journal = {"schema_version": 2, "transaction": transaction, "slot": slot,
                       "previous": original_current, "archived": current if archive else None,
                       "profile_path": hashlib.sha256(os.path.normcase(str(self.data_dir)).encode()).hexdigest(),
                       "state": "preparing", "live_digest": _tree_digest(self.data_dir),
                       "archive_digest": _tree_digest(archive) if archive else None,
                       "target_digest": None,
                       "markers": {p.name: value for p, value in originals.items()}}
            try:
                # Written before copying: a process exit at any later step leaves
                # enough evidence to recover without guessing an account identity.
                _atomic_text(self.journal_file, json.dumps(journal) + '\n')
                if archive:
                    _copy_verified(self.data_dir, archive_stage)
                # First-run target A must load the newly archived live identity.
                source = archive_stage if adopt and slot == "A" else target if target.exists() else None
                if source:
                    _copy_verified(source, live_stage)
                else:
                    live_stage.mkdir(parents=True, mode=0o700)
                    _manifest(live_stage)
                self._merge_retained(live_stage, keep_paths)
                journal.update(state='staged', target_digest=_tree_digest(live_stage))
                _atomic_text(self.journal_file, json.dumps(journal) + '\n')
                record('staged_and_verified')
                if archive:
                    if archive.exists():
                        os.replace(archive, archive_previous)
                        archive_old_moved = True
                    os.replace(archive_stage, archive)
                    archive_committed = True
                if live_exists:
                    os.replace(self.data_dir, live_previous)
                    live_old_moved = True
                os.replace(live_stage, self.data_dir)
                live_committed = True
                self._write_current(slot, originals)
                if self._read_current()!=slot:raise AccountError('Current account marker did not read back')
                if (_tree_digest(self.data_dir) != journal['target_digest']
                        or archive and _tree_digest(archive) != journal['live_digest']):
                    raise AccountError('Committed account data did not read back')
                record('committed')
                journal['state'] = 'committed'
                _atomic_text(self.journal_file, json.dumps(journal) + '\n')
                committed = True
            except Exception as exc:
                rollback_errors = []
                try:
                    if live_committed:
                        os.replace(self.data_dir, live_stage)
                    if live_old_moved:
                        os.replace(live_previous, self.data_dir)
                    if archive_committed:
                        os.replace(archive, archive_stage)
                    if archive_old_moved:
                        os.replace(archive_previous, archive)
                    for path in self._current_paths():
                        if path in originals:
                            _atomic_text(path, originals[path])
                        elif path.exists():
                            _safe_entry(path)
                            path.unlink()
                except Exception as rollback_exc:
                    rollback_errors.append(rollback_exc)
                if not rollback_errors:
                    try:
                        _remove_staging(live_stage)
                        if archive_stage:
                            _remove_staging(archive_stage)
                        if self.journal_file.exists():
                            self.journal_file.unlink()
                    except Exception as cleanup_exc:
                        rollback_errors.append(cleanup_exc)
                if rollback_errors:
                    record('recovery_required')
                    raise RecoveryRequired("Operation failed and recovery copies were retained; inspect the transaction journal and .new/.previous paths.") from exc
                record('rolled_back')
                raise AccountError("Account exchange failed; original profile, snapshot and current marker were restored.") from exc
            if committed:
                try:
                    _remove_staging(live_previous)
                    if archive_previous:
                        _remove_staging(archive_previous)
                    self.journal_file.unlink()
                    record('cleanup_complete')
                except Exception as exc:
                    raise RecoveryRequired("The exchange committed, but backup cleanup needs review; the application was not launched.") from exc
            return self._launch({"slot": slot, "previous": original_current, "changed": True}, preflight, checked_at)

    def copy_snapshot_to(self, slot, destination):
        """Verified *unencrypted* directory hook for an encryption/export layer."""
        slot = validate_slot(slot)
        destination = Path(os.path.abspath(os.fspath(destination)))
        with self._lock():
            self._require_clean(slot)
            if self._read_current() == slot:
                raise AccountError("Archive the active account before exporting its snapshot.")
            for managed in (self.state_dir, self.data_dir):
                try:
                    common = os.path.commonpath([os.path.normcase(str(managed)), os.path.normcase(str(destination))])
                except ValueError:
                    common = None
                if common in {os.path.normcase(str(managed)), os.path.normcase(str(destination))}:
                    raise AccountError("Export destination must be outside managed account and profile paths.")
            _safe_entry(destination)
            _copy_verified(self.accounts_dir / slot, destination)
        return {"slot": slot, "encrypted": False, "destination": str(destination)}

    def import_snapshot_from(self, source, slot):
        """Verified raw-directory hook; never overwrites an existing/live slot."""
        slot = validate_slot(slot)
        source = Path(os.path.abspath(os.fspath(source)))
        with self._lock():
            self._require_clean(slot)
            target = self.accounts_dir / slot
            if target.exists() or self._read_current() == slot:
                raise AccountError("Import requires an empty, inactive account slot.")
            stage = target.with_name(target.name + ".new")
            try:
                _copy_verified(source, stage)
                os.replace(stage, target)
            except Exception as exc:
                # Source is unchanged; the verified/partial stage is not a sole copy.
                try:
                    _remove_staging(stage)
                except Exception:
                    raise RecoveryRequired("Import failed; a staging copy was preserved.") from exc
                raise AccountError("Snapshot import failed; source data was preserved.") from exc
        return {"slot": slot, "imported": True}
