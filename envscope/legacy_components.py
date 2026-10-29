"""Reviewed retirement and recovery of legacy background components.

Definitions are backed up by the OS-side transaction before removal. The mixed
account directory, scripts, profiles, credentials and application data stay put.
"""
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import platform
import re
import secrets
import subprocess
import time

from .accounts import AccountError
from .component_inventory import ROLES, blocking

PENDING = ('prepared', 'partial')


def key(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def validate_snapshot(value):
    if (not isinstance(value, dict) or value.get('format') != 1 or value.get('system') not in ('Windows', 'Darwin')
            or not isinstance(value.get('actor'), str) or not value['actor'] or not isinstance(value.get('rows'), list)):
        raise ValueError('旧组件资料格式无法核实')
    ids = set()
    for row in value['rows']:
        if (not isinstance(row, dict) or row.get('id') not in ROLES or row['id'] in ids
                or type(row.get('owned')) is not bool or any(row.get(k) is not None and type(row[k]) is not bool for k in ('present', 'registered', 'enabled'))):
            raise ValueError('旧组件标识或状态无法核实')
        ids.add(row['id'])
    return value


def retirable(row):
    if (row.get('owned') is not True or row.get('error') or any(type(row.get(k)) is not bool for k in ('present', 'registered', 'enabled', 'running'))
            or row.get('present') is not True or not re.fullmatch('[a-f0-9]{64}', str(row.get('script_sha', '')))
            or not re.fullmatch('[a-f0-9]{64}', str(row.get('definition_sha', ''))) or not isinstance(row.get('definition'), str)):
        return False
    try:
        body = base64.b64decode(row['definition'], validate=True)
        return len(body) <= 256*1024 and hashlib.sha256(body).hexdigest() == row['definition_sha']
    except (ValueError, TypeError): return False


class UnavailableComponents:
    fixture = True
    def snapshot(self): raise ValueError('隔离环境未提供真实旧组件适配器')
    def status(self): return {'state': 'not_configured', 'id': ''}
    def execute(self, *args): raise ValueError('当前环境不执行系统组件修改')


def native_io(home):
    if platform.system() == 'Windows':
        from .components_windows import WindowsComponents
        return WindowsComponents(home)
    if platform.system() == 'Darwin':
        from .components_macos import MacComponents
        return MacComponents(home)
    return UnavailableComponents()


class ComponentMigration:
    def __init__(self, store, home=None, *, io=None, transaction_lock=None, replacements=None, clock=time.monotonic):
        self.store, self.home = store, Path(home or Path.home()).resolve()
        self.io = io or native_io(self.home)
        self.clock, self.plans, self.cached = clock, {}, None
        self.transaction_lock = transaction_lock
        self.replacements = replacements or (lambda: {})

    def _snapshot(self): return validate_snapshot(self.io.snapshot())

    def peek(self):
        if not self.cached:
            return {'state': 'not_checked', 'rows': [], 'can_restore': False, 'needs_recovery': False,
                    'reason': '进入持续维护后自动读取旧组件。此处只核对系统任务，账号与原脚本保留。'}
        return {**deepcopy(self.cached[1]), 'cached': True, 'cache_age_seconds': round(max(0, self.clock()-self.cached[0]))}

    def status(self, fresh=False):
        if not fresh and self.cached and self.clock()-self.cached[0] < 10:
            return {**deepcopy(self.cached[1]), 'cached': True}
        try:
            snapshot, receipt = self._snapshot(), self.io.status()
            value = {'state': receipt.get('state', 'not_configured'), 'receipt': receipt,
                     'rows': [{k: r.get(k) for k in ('id', 'title', 'scope', 'label', 'path', 'script', 'present', 'registered', 'owned', 'running', 'enabled', 'error', 'reason')} for r in snapshot['rows']],
                     'can_restore': bool(receipt.get('id') and receipt.get('state') in (*PENDING, 'committed')),
                     'needs_recovery': receipt.get('state') in PENDING,
                     'reason': '仅核对旧后台任务；账号、脚本与应用资料保留。删除登记不等于新保护已启用，迁移后还需重新检测并审核原生守护。'}
        except (OSError, ValueError, AccountError) as error:
            value = {'state': 'unavailable', 'rows': [], 'can_restore': False, 'needs_recovery': False, 'reason': str(error)[:240]}
        self.cached = self.clock(), deepcopy(value)
        return value

    def conflict(self, role='guard'):
        try: return blocking(self._snapshot(), role)
        except (OSError, ValueError, AccountError): return True

    def prepare(self, roles=None, *, restore=False):
        if type(restore) is not bool: raise ValueError('恢复选项需要明确的布尔值')
        if roles is not None and (not isinstance(roles, list) or not roles or len(roles) > 4
                or any(r not in ROLES for r in roles) or len(set(roles)) != len(roles)):
            raise ValueError('请选择已列出的旧组件')
        try:
            snapshot, receipt = self._snapshot(), self.io.status()
            if restore:
                if receipt.get('state') not in (*PENDING, 'committed') or not re.fullmatch('[a-f0-9]{32}', str(receipt.get('id', ''))):
                    return {'state': 'guided', 'reason': '没有可恢复的旧组件事务；不会根据未知原值创建任务。'}
                if receipt.get('actor') != snapshot['actor']:
                    return {'state': 'guided', 'reason': '恢复记录属于另一用户，保留副本，请由原用户核对。'}
                selected = receipt.get('roles', [])
                if roles is not None and set(roles) != set(selected): raise ValueError('恢复使用整笔已保存事务，不混合其他范围')
                replacements = self.replacements()
                if ('guard' in selected and replacements.get('guard') or 'timezone' in selected and replacements.get('timezone')):
                    return {'state': 'guided', 'reason': '对应的 EnvScope 原生守护仍在启用。先停用原生守护，再恢复旧任务，避免两个守护同时运行。'}
                effects = ['核对受保护的原始任务定义、权限和当前状态，恢复整笔旧组件事务；保留全部备份与日志',
                           '恢复前必须确认对应原生守护已停用；不会合并后来出现的同名任务或改写外部新配置',
                           '仅恢复原先登记的任务；原先暂停 / 未登记的任务保持原状态，不自动打开旧界面或 Claude',
                           '恢复已登记的旧任务时，RunAtLoad 或定时条件可能立即执行原脚本：停止 Claude、设置旧时区或检查旧核心更新；这不是新的 EnvScope 保护',
                           '账号资料、原脚本和原应用目录不删除、不交换；脚本后来改变时停止恢复，交由手动处理']
            else:
                if receipt.get('state') in PENDING:
                    return {'state': 'guided', 'reason': '上次旧组件事务未完成，先预览恢复；未丢弃任何副本。'}
                rows = snapshot['rows']
                selected = roles if roles is not None else [r['id'] for r in rows if r.get('owned') and (r.get('present') or r.get('registered'))]
                if not selected: return {'state': 'not_needed', 'reason': '没有可自动迁移的已识别旧任务；未知或权限拒绝的项目请按说明处理。'}
                if receipt.get('state') == 'committed':
                    return {'state': 'guided', 'reason': '已有可恢复的迁移记录，未用新事务覆盖它。需要改变迁移范围时，先停用对应原生保护、恢复原事务，再一次选择所需旧组件。'}
                found = {r['id']: r for r in rows}
                if any(r not in found or not retirable(found[r]) for r in selected):
                    return {'state': 'guided', 'reason': '所选任务的定义、账户、权限或脚本尚未核实，未停止或覆盖；请在系统任务入口核对。'}
                if any(found[r].get('present') is not True and found[r].get('registered') is not True for r in selected):
                    return {'state': 'not_needed', 'reason': '所选旧任务未安装，无需停用。'}
                effects = ['先保存每个所选任务的完整原定义、权限、程序摘要与登记 / 运行状态，再停止并移除它的系统登记',
                           '仅处理：'+ '、'.join(ROLES[r] for r in selected),
                           '旧任务停用后会出现保护间隔；自动复检后，再单独审核 EnvScope 原生保护，收到新心跳后才算生效',
                           '原先暂停的任务不会被启动；不删除账号存档、凭据、应用资料、原脚本或旧界面',
                           '中断或失败保留恢复记录；恢复时核对当前定义与原脚本，后续变更不覆盖',
                           '请先退出旧版界面及手动运行的旧脚本；本操作只停止调度器管理的任务，不按程序名批量结束进程']
            token = secrets.token_urlsafe(24); ident = secrets.token_hex(16)
            self.plans = {token: {'snapshot': snapshot, 'receipt': receipt, 'roles': selected, 'restore': restore,
                                  'deadline': self.clock()+90, 'id': ident}}
            return {'state': 'planned', 'plan_id': token, 'effects': effects, 'roles': selected,
                    'reason': '审核所列范围后确认；需要系统权限时只为本次操作申请授权。'}
        except (OSError, ValueError, AccountError) as error:
            return {'state': 'guided', 'reason': str(error)[:240]}

    def apply(self, token, confirmed=False):
        if confirmed is not True: return {'state': 'confirmation_required'}
        plan = self.plans.get(token) if isinstance(token, str) else None
        if not plan or self.clock() > plan['deadline']:
            return {'state': 'retest_required', 'reason': '方案已过期，请重新读取旧组件并预览。'}
        from contextlib import nullcontext
        try:
            with self.transaction_lock() if self.transaction_lock else nullcontext():
                snapshot, receipt = self._snapshot(), self.io.status()
                if key(snapshot) != key(plan['snapshot']) or key(receipt) != key(plan['receipt']):
                    return {'state': 'retest_required', 'reason': '组件或恢复记录已经改变，未执行旧方案。'}
                if plan['restore']:
                    active = self.replacements()
                    if any(active.get(r) for r in plan['roles'] if r in ('guard', 'timezone')):
                        return {'state': 'retest_required', 'reason': '原生守护状态改变，未恢复冲突的旧任务。'}
                payload = {'format': 1, 'actor': snapshot['actor'], 'id': plan['id'], 'roles': plan['roles'],
                           'expected_record': receipt.get('id', ''), 'before': snapshot['rows']}
                self.io.execute('restore' if plan['restore'] else 'retire', payload)
                after = self.io.status(); live = self._snapshot(); found = {r['id']: r for r in live['rows']}
                wanted = 'restored' if plan['restore'] else 'committed'
                ok = (after.get('state') == wanted and after.get('id') == (receipt.get('id') if plan['restore'] else plan['id']))
                if plan['restore']:
                    originals = {r['id']: r for r in after.get('original', [])}
                    ok = ok and set(originals) == set(plan['roles'])
                    for role in plan['roles']:
                        row, original = found.get(role, {}), originals.get(role, {})
                        keys = ('present', 'registered', 'enabled', 'script_sha') + (('definition_sha', 'mode', 'group') if snapshot['system'] == 'Darwin' else ())
                        ok = ok and row.get('owned') is True and not row.get('error') and all(row.get(k) == original.get(k) for k in keys)
                else:
                    ok = ok and all(found.get(r, {}).get('present') is False and found[r].get('registered') is False and not found[r].get('error') for r in plan['roles'])
                self.plans.clear(); self.cached = None
                return {'state': 'restored' if ok and plan['restore'] else 'completed' if ok else 'partial', 'retest': True,
                        'reason': '原任务已按保存范围恢复，需重新检测实际状态。' if ok and plan['restore'] else
                                  '旧任务登记已独立读回为移除；资料和恢复副本保留。现在重新检测，再审核原生保护。' if ok else
                                  '组件操作未完全读回，保留现场与恢复记录，请先处理恢复入口。'}
        except (OSError, ValueError, AccountError, subprocess.TimeoutExpired) as error:
            self.cached = None
            return {'state': 'partial', 'reason': str(error)[:240], 'recovery': self.status(True)}
