"""Reviewed native routing with durable intent, readback and conservative undo."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import time

from .baseline import DOMAINS, verify_rules
from .discovery import config_directories
from .event_log import append_event
from .local_controller import from_config
from .remedies import ConfigRemedies, SolutionPlans, _read, _replace, _safe
from .routing_config import load_yaml, rule_strings, update_script, update_yaml_rules
from .target_environment import fingerprint

FILES = {'script': 'profiles/Script.js', 'runtime': 'clash-verge.yaml'}
PENDING = {'writing', 'loaded', 'rolling_back', 'partial'}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    path = _safe(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('配置必须为独立的普通文件')
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('配置超过 1 MiB，请在客户端处理')
    return raw


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def _rule_view(value):
    entries = value.get('rules')
    if not isinstance(entries, list) or any(not isinstance(r, dict) for r in entries):
        raise ValueError('运行规则格式无效')
    return [{k: r.get(k) for k in ('type', 'payload', 'proxy')} |
            {'disabled': r.get('disabled') is True or isinstance(r.get('extra'), dict) and r['extra'].get('disabled') is True}
            for r in entries]


def _chain(snapshot, group):
    nodes = snapshot['proxies'].get('proxies', {})
    result, name = [], group
    for _ in range(32):
        item = nodes.get(name)
        if not isinstance(item, dict) or any(row['name'] == name for row in result):
            raise ValueError('代理组不存在或有循环引用')
        result.append({'name': name, **{k: item.get(k) for k in ('type', 'all', 'now', 'udp')}})
        if 'now' not in item and 'all' not in item:
            return result
        name = item.get('now')
        if not isinstance(name, str):
            break
    raise ValueError('无法确认代理组实际节点')


def _stamp(snapshot, group):
    return digest(_json({'config': snapshot['configs'], 'rules': _rule_view(snapshot['rules']),
                         'chain': _chain(snapshot, group)}))


def expected_runtime(group, policy):
    return {'rules': [{'type': 'And', 'payload': f'((NETWORK,UDP),(DST-PORT,{p}))',
                       'proxy': 'REJECT' if policy == 'reject' else group} for p in (3478, 5349, 19302)] +
                     [{'type': 'DomainSuffix', 'payload': domain, 'proxy': group} for domain in DOMAINS]}


class Routing:
    def __init__(self, store, home=None, system=None, environ=None, controller=None):
        self.store = store
        self.home = (Path(home) if home else Path.home()).resolve()
        self.system = system or platform.system()
        self.environ = os.environ if environ is None else environ
        self.controller_factory = controller or (lambda config: from_config(config, self.system))
        self.root = store.root / 'routing'
        self.locker = ConfigRemedies(self.home, self.home)
        self.locker.backups = self.root
        self.plans, self.undo_plans = {}, {}

    def directories(self):
        return config_directories(self.home, self.system, self.environ)

    def _directory(self):
        candidates = [p for p in self.directories() if read(p / 'clash-verge.yaml') is not None]
        if len(candidates) != 1:
            raise ValueError('未找到唯一的 Clash Verge 运行配置；请先打开客户端，多个资料目录时先在客户端整理')
        return candidates[0]

    def _context(self, directory=None):
        directory = directory or self._directory()
        if directory not in self.directories():
            raise ValueError('配置目录已变化，请在原客户端手动恢复')
        files = {key: read(directory / value) for key, value in FILES.items()}
        _, config = load_yaml(files['runtime'])
        profiles = read(directory / 'profiles.yaml')
        _, index = load_yaml(profiles)
        items = index.get('items')
        scripts = [i for i in items if isinstance(i, dict) and i.get('uid') == 'Script'] if isinstance(items, list) else []
        if len(scripts) != 1 or scripts[0].get('file') != 'Script.js' or scripts[0].get('type') != 'script':
            raise ValueError('未识别到启用的全局 Script.js；请先在 Clash Verge 的配置页初始化全局扩展脚本')
        if config.get('mode') != 'rule':
            raise ValueError('此修复用于规则模式；请先在代理客户端选择规则模式后复检')
        if not files['script']:
            raise ValueError('全局脚本为空，请先在 Clash Verge 初始化脚本入口')
        guards = {'profiles.yaml': digest(profiles)}
        controller = self.controller_factory(config)
        return directory, files, config, guards, controller

    def _record(self):
        pointer = read(self.root / 'latest.private.json')
        if pointer is None:
            return None
        index = json.loads(pointer)
        ident = index.get('id') if isinstance(index, dict) else None
        if not isinstance(ident, str) or not re.fullmatch('[0-9a-f]{32}', ident):
            raise ValueError('路由恢复索引损坏，请保留恢复目录')
        record = json.loads(read(self.root / ident / 'record.private.json') or b'null')
        if (not isinstance(record, dict) or record.get('id') != ident or record.get('version') != 1 or
                record.get('state') not in PENDING | {'committed', 'rolled_back'} or
                set(record.get('files', {})) != set(FILES) or
                Path(record.get('directory', '')) not in self.directories()):
            raise ValueError('路由恢复记录无法识别，请保留恢复目录并在客户端手动核对')
        return record

    def _save(self, record, state):
        record['state'] = state
        record['updated_at'] = datetime.now(timezone.utc).isoformat()
        path = self.root / record['id'] / 'record.private.json'
        _replace(path, _json(record), read(path))
        append_event(self.root / 'events', {'at': record['updated_at'], 'kind': state,
                                           'transaction': record['id'], 'text': {
                                               'writing': '已备份，准备写入路由配置',
                                               'loaded': '已请求内核加载，正在读回规则',
                                               'committed': '本次运行规则已验证；客户端下次重新生成后仍需巡检',
                                               'rolling_back': '正在恢复原配置与运行规则',
                                               'rolled_back': '原配置与原运行规则已核对恢复',
                                               'partial': '恢复未完成；保留全部副本，需继续处理'}[state]})

    def status(self):
        try:
            record = self._record()
            if not record:
                return {'state': 'not_configured', 'reason': '尚未通过 EnvScope 配置路由。'}
            return {'state': record['state'], 'at': record['updated_at'], 'can_undo': record['state'] != 'rolled_back',
                    'reason': ('上次写入后的运行规则已核对；当前结果以重新检测为准。' if record['state'] == 'committed' else
                               '已恢复原配置；请重新检测当前环境。' if record['state'] == 'rolled_back' else
                               '存在未完成的路由事务，请先预览恢复；全部备份已保留。'),
                    'backup_path': str(self.root / record['id'])}
        except (OSError, ValueError, TypeError):
            return {'state': 'invalid', 'reason': '路由恢复记录无法安全读取，请保留恢复目录并在客户端手动核对。',
                    'backup_path': str(self.root)}

    def options(self):
        try:
            _, _, config, _, controller = self._context()
            snapshot = controller.snapshot()
            if snapshot['configs'].get('mode') != 'rule':
                raise ValueError('当前内核不是规则模式，请在代理客户端调整后复检')
            groups = [g.get('name') for g in config.get('proxy-groups', []) if isinstance(g, dict)]
            available = []
            policy = self.store.settings()['webrtc_policy']
            for group in groups:
                try:
                    rule_strings(group, policy)
                    checked = verify_rules(snapshot['configs'], expected_runtime(group, policy), snapshot['proxies'],
                                           {'proxy_group': group, 'webrtc_policy': policy})
                    if checked['status'] == 'pass':
                        available.append(group)
                except ValueError:
                    continue
            return {'state': 'available', 'groups': available,
                    'reason': '仅列出当前已选实际代理节点、符合 UDP 策略的组；组名不证明出口地区。'}
        except (ValueError, OSError, TypeError) as error:
            return {'state': 'guided', 'groups': [], 'reason': str(error) if isinstance(error, ValueError) else '无法读取客户端配置，请检查读取权限。'}

    def _fresh(self, report):
        settings = self.store.settings()
        if (not SolutionPlans._current(report) or not settings.get('environment_confirmed') or
                report.get('environment', {}).get('fingerprint') != fingerprint(settings)):
            raise ValueError('请先按当前目标重新检测，再预览路由方案')
        from .regions import region_finding, PARTIAL
        if (not settings.get('usage_country') or settings['usage_country'] in PARTIAL or
                region_finding([], settings).status.value == 'fail' or
                any(f['id'] == 'target.region' and f['status'] == 'fail' for f in report.get('findings', []))):
            raise ValueError('实际地区未确认或不符合官方支持条件；更改路由不能改变使用资格')
        return settings

    def prepare(self, report, group=None):
        try:
            settings = self._fresh(report)
            if settings.get('client') not in ('auto', 'clash-verge'):
                raise ValueError('当前客户端不使用 Clash Verge 全局脚本，请在所选客户端配置置顶规则后复检')
            record = self._record()
            if record and record['state'] in PENDING:
                raise ValueError('上次路由事务未完成，请先预览恢复，未覆盖原记录')
            directory, files, config, guards, controller = self._context()
            group = group or settings.get('proxy_group')
            policy = settings['webrtc_policy']
            if not group:
                choices = self.options().get('groups', [])
                if len(choices) != 1:
                    raise ValueError('请在持续维护的路由配置中读取并选择目标代理组')
                group = choices[0]
            if settings.get('proxy_group') and group != settings['proxy_group']:
                raise ValueError('所选代理组与检测目标不同，请先调整设置并重新检测')
            pinned = rule_strings(group, policy)
            if not any(isinstance(g, dict) and g.get('name') == group for g in config.get('proxy-groups', [])):
                raise ValueError('目标代理组不在当前配置中')
            snapshot = controller.snapshot()
            if snapshot['configs'].get('mode') != 'rule':
                raise ValueError('当前内核不是规则模式，未改写配置')
            checked = verify_rules(snapshot['configs'], expected_runtime(group, policy), snapshot['proxies'],
                                   {'proxy_group': group, 'webrtc_policy': policy})
            if checked['status'] != 'pass':
                raise ValueError(checked['reason'] + '；请先在代理客户端处理节点')
            after = {'script': update_script(files['script'], group, pinned), 'runtime': update_yaml_rules(files['runtime'], pinned)}
            token = secrets.token_urlsafe(24)
            self.plans = {token: {'directory': directory, 'before': files, 'after': after, 'guards': guards,
                                  'controller': controller.identity, 'snapshot': snapshot, 'group': group, 'policy': policy,
                                  'stamp': _stamp(snapshot, group), 'fingerprint': fingerprint(settings),
                                  'report_id': report['report_id'], 'deadline': time.monotonic() + 90}}
            return {'state': 'planned', 'plan_id': token, 'rules': pinned, 'group': group,
                    'effects': ['备份全局 Script.js 和 clash-verge.yaml；保留原用户脚本，追加 13 个域名与 3 个 UDP 端口规则',
                                '将规则置顶到组「' + group + '」；UDP 端口将' + ('拒绝连接，可能影响语音 / 视频通话' if policy == 'reject' else '通过当前支持 UDP 的节点'),
                                '重新加载当前完整内核配置，可能短暂中断此代理承载的其他应用；不主动切换节点',
                                '读回规则顺序、目标与节点；失败时恢复原文件并重载，结果不一致则保留恢复记录',
                                '全局扩展影响使用该脚本的订阅；客户端下次重新生成后仍需巡检，运行规则不等于流量或账号可用性证明'],
                    'reason': '核对下列影响后确认；只验证本次实际加载状态。'}
        except (ValueError, OSError, TypeError) as error:
            return {'state': 'guided', 'effects': [], 'reason': str(error) if isinstance(error, ValueError) else '无法安全读取配置，请在客户端核对文件权限。'}

    def apply(self, token, report, confirmed=False):
        if confirmed is not True:
            return {'state': 'confirmation_required', 'reason': '请先核对路由方案并明确确认'}
        plan = self.plans.get(token) if isinstance(token, str) else None
        if not plan or time.monotonic() > plan['deadline']:
            return {'state': 'retest_required', 'reason': '方案已过期，请重新检测并生成方案'}
        with self.locker._lock():
            settings = self._fresh(report)
            if plan['report_id'] != report['report_id'] or plan['fingerprint'] != fingerprint(settings):
                raise ValueError('检测目标已变化，未执行旧方案')
            pending = self._record()
            if pending and pending['state'] in PENDING:
                raise ValueError('上次事务未完成，请先恢复')
            directory, files, _, guards, controller = self._context(plan['directory'])
            if (files != plan['before'] or guards != plan['guards'] or controller.identity != plan['controller'] or
                    _stamp(controller.snapshot(), plan['group']) != plan['stamp']):
                raise ValueError('配置、运行规则或节点在预览后变化，未覆盖，请重新检测')
            self._fresh(report)
            if time.monotonic() > plan['deadline']:
                raise ValueError('确认期间方案已过期，未写入')
            del self.plans[token]
            ident = secrets.token_hex(16)
            folder = self.root / ident
            record = {'version': 1, 'id': ident, 'directory': str(directory), 'controller': controller.identity,
                      'group': plan['group'], 'policy': plan['policy'], 'stamp': plan['stamp'], 'files': {}}
            for key in FILES:
                for stage in ('before', 'after'):
                    _replace(folder / (key + '-' + stage + '.private.bin'), plan[stage][key], None)
                record['files'][key] = {stage: digest(plan[stage][key]) for stage in ('before', 'after')}
            self._save(record, 'writing')
            _replace(self.root / 'latest.private.json', _json({'id': ident}), read(self.root / 'latest.private.json'))
            try:
                for key, name in FILES.items():
                    _replace(directory / name, plan['after'][key], plan['before'][key])
                controller.reload(directory / FILES['runtime'])
                self._save(record, 'loaded')
                observed = controller.snapshot()
                check = verify_rules(observed['configs'], observed['rules'], observed['proxies'],
                                     {'proxy_group': plan['group'], 'webrtc_policy': plan['policy']})
                if (check['status'] != 'pass' or observed['configs'].get('mode') != 'rule' or
                        _chain(observed, plan['group']) != _chain(plan['snapshot'], plan['group']) or
                        any(read(directory / FILES[k]) != plan['after'][k] for k in FILES) or
                        any(digest(read(directory / name) or b'') != val for name, val in guards.items())):
                    raise ValueError('加载后核对未通过')
                self._save(record, 'committed')
                return {'state': 'completed', 'needs_retest': True, 'verification': check,
                        'reason': '已写入并核对本次运行的 16 条规则及实际节点。现在重新检测；下次客户端重新生成后仍需巡检。'}
            except (OSError, ValueError, TypeError):
                return self._rollback(record, controller)

    def _restore_material(self, record):
        directory = Path(record['directory'])
        result = {}
        for key, name in FILES.items():
            material = {}
            for stage in ('before', 'after'):
                raw = read(self.root / record['id'] / (key + '-' + stage + '.private.bin'))
                if raw is None or digest(raw) != record['files'][key].get(stage):
                    raise ValueError('备份校验失败；未覆盖当前配置，请保留所有文件')
                material[stage] = raw
            current = read(directory / name)
            if current not in (material['before'], material['after']):
                raise ValueError('配置存在后续编辑；未覆盖，请在客户端对照备份手动合并')
            material['current'] = current
            result[key] = material
        return result

    def _rollback(self, record, controller):
        try:
            material = self._restore_material(record)
            if controller.identity != record['controller']:
                raise ValueError('控制接口已变化')
            self._save(record, 'rolling_back')
            directory = Path(record['directory'])
            for key, values in material.items():
                _replace(directory / FILES[key], values['before'], values['current'])
            controller.reload(directory / FILES['runtime'])
            if (_stamp(controller.snapshot(), record['group']) != record['stamp'] or
                    any(read(directory / FILES[k]) != material[k]['before'] for k in FILES)):
                raise ValueError('原运行状态未确认恢复')
            self._save(record, 'rolled_back')
            return {'state': 'rolled_back', 'needs_retest': True,
                    'reason': '已恢复修改前的文件与运行规则。若本次修复失败，请在客户端查看配置错误后重新检测。'}
        except (OSError, ValueError, TypeError):
            self._save(record, 'partial')
            return {'state': 'partial', 'needs_retest': True,
                    'reason': '恢复未全部完成：文件可能已恢复，但运行状态尚未确认，或文件存在后续编辑。保留全部备份；请在客户端核对并重新加载后继续恢复。'}

    def undo_prepare(self):
        try:
            record = self._record()
            if not record or record['state'] == 'rolled_back':
                return {'state': 'guided', 'reason': '没有待恢复的路由事务'}
            material = self._restore_material(record)
            token = secrets.token_urlsafe(24)
            self.undo_plans = {token: {'id': record['id'], 'state': record['state'],
                                       'files': {k: digest(v['current']) for k, v in material.items()},
                                       'deadline': time.monotonic() + 90}}
            return {'state': 'planned', 'plan_id': token,
                    'effects': ['恢复此次路由修改前的两个原文件；如有后续编辑则停止，不覆盖',
                                '在原本机控制接口重载原配置，可能短暂中断此代理承载的其他应用',
                                '核对原规则和原节点；接口离线或状态不同则保留记录，提示手动处理'],
                    'reason': '请核对恢复范围；备份将继续保留。'}
        except (OSError, ValueError, TypeError) as error:
            return {'state': 'guided', 'reason': str(error) if isinstance(error, ValueError) else '无法读取恢复文件，请保留目录并手动核对'}

    def undo(self, token, confirmed=False):
        if confirmed is not True:
            return {'state': 'confirmation_required', 'reason': '请先预览并确认恢复范围'}
        plan = self.undo_plans.get(token) if isinstance(token, str) else None
        if not plan or time.monotonic() > plan['deadline']:
            return {'state': 'retest_required', 'reason': '恢复方案已过期，请重新预览'}
        with self.locker._lock():
            record = self._record()
            if not record or record['id'] != plan['id'] or record['state'] != plan['state']:
                raise ValueError('恢复事务已变化，请重新预览')
            material = self._restore_material(record)
            if {k: digest(v['current']) for k, v in material.items()} != plan['files']:
                raise ValueError('配置在预览后发生变化，请重新预览恢复')
            _, config = load_yaml(material['runtime']['before'])
            controller = self.controller_factory(config)
            del self.undo_plans[token]
            return self._rollback(record, controller)
