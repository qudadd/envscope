"""Reviewed recovery of interrupted whole-profile exchanges; never auto-launch.

Journal paths are derived from validated slots, not supplied by the caller.
Displaced trees are renamed next to their originals and are never deleted here.
The same plan can be rebuilt after interruption during recovery itself.
"""
import hashlib
import json
import os
import re
import time
import uuid

from .accounts import (AccountError, RecoveryRequired, _atomic_text, _copy_verified,
                       _safe_chain, _tree_digest, validate_slot)
from .event_log import append_event
from .model import utc_now


class AccountRecovery:
    def __init__(self, manager):
        self.manager = manager
        self.plans = {}

    def _journal(self):
        manager = self.manager
        manager._check_roots()
        path = manager.journal_file
        if not path.is_file() or path.stat().st_size > 16384:
            raise RecoveryRequired('没有可读取的账号事务记录；请保留现有目录并手动核对。')
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
            keys = {'schema_version', 'transaction', 'slot', 'previous', 'archived', 'profile_path',
                    'state', 'live_digest', 'archive_digest', 'target_digest', 'markers'}
            if not isinstance(value, dict) or set(value) != keys or value['schema_version'] != 2:
                raise ValueError('schema')
            if not isinstance(value['transaction'], str) or not re.fullmatch('[0-9a-f]{32}', value['transaction']):
                raise ValueError('transaction')
            for key in ('slot', 'previous', 'archived'):
                if value[key] is not None or key == 'slot':
                    if validate_slot(value[key]) != value[key]:
                        raise ValueError('slot')
            if value['archived'] not in (None, value['previous'] or 'A'):
                raise ValueError('archive')
            if value['profile_path'] != hashlib.sha256(os.path.normcase(str(manager.data_dir)).encode()).hexdigest():
                raise ValueError('profile location')
            if value['state'] not in ('preparing', 'staged', 'committed'):
                raise ValueError('state')
            for key in ('live_digest', 'archive_digest', 'target_digest'):
                if value[key] is not None and (not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{64}', value[key])):
                    raise ValueError('digest')
            if value['state'] != 'preparing' and value['target_digest'] is None:
                raise ValueError('target')
            if value['archived'] is None and value['archive_digest'] is not None:
                raise ValueError('archive digest')
            markers = value['markers']
            if not isinstance(markers, dict) or set(markers) - {'current', 'current.txt'}:
                raise ValueError('markers')
            for text in markers.values():
                if not isinstance(text, str) or len(text) > 256:
                    raise ValueError('marker text')
                content = text.strip()
                actual = None if content in ('', 'none') else validate_slot(content)
                if actual != value['previous']:
                    raise ValueError('marker identity')
            if value['previous'] is not None and not markers:
                raise ValueError('missing markers')
        except (ValueError, TypeError, KeyError, AccountError) as error:
            raise RecoveryRequired('事务记录过旧或校验不通过，已保留现场。请勿手动删除 .new / .previous；先复制保存，再核对所属账号。') from error
        return value

    def status(self):
        if not os.path.lexists(self.manager.journal_file):
            return {'available': False, 'reason': '没有可自动核验的事务记录。遗留副本需手动核对。'}
        try:
            value = self._journal()
            return {'available': True, 'reason': '有未完成的资料交换，先检查可恢复方案。',
                    'transaction': value['transaction']}
        except (AccountError, OSError) as error:
            return {'available': False, 'reason': str(error)}

    def _paths(self, value):
        paths = {'live': self.manager.data_dir}
        if value['archived']:
            paths['archive'] = self.manager.accounts_dir / value['archived']
        roots = dict(paths)
        for name, path in roots.items():
            paths[name + '_new'] = path.with_name(path.name + '.new')
            paths[name + '_previous'] = path.with_name(path.name + '.previous')
            paths[name + '_restore'] = path.with_name(path.name + '.restore-' + value['transaction'])
        for name, path in list(paths.items()):
            if not name.endswith('_restore'):
                paths[name + '_saved'] = path.with_name(path.name + '.recovered-' + value['transaction'])
        return paths

    def _inspect(self):
        value = self._journal()
        paths = self._paths(value)
        expected_pending = {'account-transaction.json', 'profile/' + paths['live_new'].name,
                            'profile/' + paths['live_previous'].name}
        if 'archive' in paths:
            expected_pending.update('accounts/' + paths[key].name for key in ('archive_new', 'archive_previous'))
        if set(self.manager._pending()) - expected_pending:
            raise RecoveryRequired('发现其他未归属本次事务的副本，请先手动核对；不会合并账号资料。')
        inventory = {name: _tree_digest(path) for name, path in paths.items()}
        markers = {}
        for path in self.manager._current_paths():
            _safe_chain(path)
            if os.path.lexists(path):
                if not path.is_file() or path.stat().st_size > 256:
                    raise RecoveryRequired('账号标记无法读取，保留现场。')
                markers[path.name] = path.read_text(encoding='utf-8-sig')
        mode = 'finish' if value['state'] == 'committed' else 'rollback'
        desired = {'live': value['target_digest'] if mode == 'finish' else value['live_digest']}
        if 'archive' in paths:
            desired['archive'] = value['live_digest'] if mode == 'finish' else value['archive_digest']
        sources = {}
        for role, digest in desired.items():
            if digest is None:
                continue
            candidates = [key for key, item in inventory.items() if item == digest]
            if not candidates:
                raise RecoveryRequired('找不到与事务校验值一致的完整资料；请保留所有副本，不能猜测恢复。')
            sources[role] = role if role in candidates else candidates[0]
        if mode == 'finish':
            # A client launched outside EnvScope may have changed the committed
            # profile. Do not replace newer live data with an old snapshot.
            if any(inventory[role] != digest for role, digest in desired.items()):
                raise RecoveryRequired('提交后的活动资料发生变化，请手动核对，不能覆盖新数据。')
            if not markers or any(text.strip() != value['slot'] for text in markers.values()):
                raise RecoveryRequired('提交后的账号标记不一致，请手动核对。')
        token = hashlib.sha256(json.dumps([value, inventory, markers], sort_keys=True).encode()).hexdigest()
        return value, paths, inventory, markers, mode, desired, sources, token

    def plan(self):
        try:
            inspected = self._inspect()
        except (AccountError, OSError, ValueError) as error:
            return {'state': 'blocked', 'reason': str(error), 'effects': [], 'manual':
                    '请先退出 Claude，保留并复制 .new、.previous 和 account-transaction.json，再核对资料所属账号。不要删除恢复副本或反复切换。'}
        value, _, _, _, mode, _, _, token = inspected
        identifier = uuid.uuid4().hex
        self.plans = {identifier: (time.monotonic(), token)}
        slot = value['slot'] if mode == 'finish' else value['previous']
        effects = ['正常退出 Claude，退出未确认则不修改资料。',
                   ('保留已提交的目标资料并收尾。' if mode == 'finish' else '恢复切换前的完整资料与账号标记。'),
                   '所有剩余副本改名为 .recovered-事务号，保存在原目录旁，不删除。',
                   '逐文件校验后解除切换锁定；本次恢复不会启动应用或登录账号。']
        return {'state': 'planned', 'plan_id': identifier, 'mode': mode, 'slot': slot,
                'reason': '可完成已提交的交换。' if mode == 'finish' else '可恢复切换前的资料。', 'effects': effects}

    def apply(self, plan_id, confirmed=False):
        if confirmed is not True:
            return {'state': 'confirmation_required', 'reason': '请审核恢复方案后确认。'}
        plan = self.plans.pop(plan_id, None) if isinstance(plan_id, str) else None
        if not plan or time.monotonic() - plan[0] > 300:
            raise RecoveryRequired('恢复方案已过期，请重新检查。')
        manager = self.manager
        with manager._lock():
            inspected = self._inspect()
            if inspected[-1] != plan[1]:
                raise RecoveryRequired('资料在预览后发生变化，请重新检查恢复方案。')
            if not callable(manager.stop_app) or manager.stop_app() is not True:
                raise AccountError('Claude 退出未确认，未修改账号资料。请先正常退出后重试。')
            # Closing a live app can flush new state. Never discard that state.
            inspected = self._inspect()
            if inspected[-1] != plan[1]:
                raise RecoveryRequired('退出应用后资料发生变化，请重新检查恢复方案。')
            value, paths, inventory, _, mode, desired, sources, _ = inspected
            def record(phase):
                append_event(manager.state_dir / 'account-events', {'at': utc_now(), 'kind': 'account_recovery',
                             'transaction': value['transaction'], 'phase': phase, 'mode': mode})
            record('confirmed')
            # Prepare all missing destinations before moving any existing tree.
            for role, digest in desired.items():
                if digest is None or inventory[role] == digest:
                    continue
                stage = paths[role + '_restore']
                if os.path.lexists(stage):
                    if _tree_digest(stage) != digest:
                        raise RecoveryRequired('恢复暂存副本不完整，已保留；请手动核对。')
                else:
                    _copy_verified(paths[sources[role]], stage)
                if _tree_digest(stage) != digest:
                    raise RecoveryRequired('恢复暂存校验失败，已保留全部资料。')
            def preserve(role):
                path = paths[role]
                if not os.path.lexists(path):
                    return
                backup = paths[role + '_saved']
                _safe_chain(path)
                _safe_chain(backup)
                if os.path.lexists(backup):
                    raise RecoveryRequired('同名恢复备份已存在；不会覆盖，请手动核对。')
                os.replace(path, backup)
            for role, digest in desired.items():
                if _tree_digest(paths[role]) == digest:
                    continue
                preserve(role)
                if digest is not None:
                    os.replace(paths[role + '_restore'], paths[role])
            for role in desired:
                for suffix in ('_new', '_previous'):
                    preserve(role + suffix)
            if any(_tree_digest(paths[role]) != digest for role, digest in desired.items()):
                raise RecoveryRequired('恢复后校验未通过，保留事务锁定。')
            if mode == 'rollback':
                for path in manager._current_paths():
                    if path.name in value['markers']:
                        _atomic_text(path, value['markers'][path.name])
                    elif os.path.lexists(path):
                        backup = path.with_name(path.name + '.recovered-' + value['transaction'])
                        _safe_chain(backup)
                        if os.path.lexists(backup):
                            raise RecoveryRequired('标记恢复备份已存在，保留现场。')
                        os.replace(path, backup)
            expected = value['slot'] if mode == 'finish' else value['previous']
            if manager._read_current() != expected:
                raise RecoveryRequired('恢复后的账号标记不一致，保留事务锁定。')
            record('verified')
            manager.journal_file.unlink()
            return {'state': 'completed', 'reason': '账号资料已恢复并核验。恢复副本已保留；应用未启动。',
                    'slot': expected, 'mode': mode, 'launched': False,
                    'preserved_copies': sum(path.exists() for key, path in paths.items() if key.endswith('_saved'))}
