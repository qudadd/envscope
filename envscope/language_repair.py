"""Reviewed Claude-only language preference changes with durable typed originals."""
from contextlib import nullcontext
from datetime import datetime,timezone
import os
from pathlib import Path
import platform
import re
import secrets

from .client_repair import digest,encoded
from .event_log import append_event
from .mac_preferences import ClaudePreferences,DOMAIN,HOSTS,language_array,validate_snapshot
from .remedies import ConfigRemedies,SolutionPlans,_replace,_safe
from .routing import read
from .target_environment import fingerprint

PENDING={'prepared','writing','rolling_back','partial'}
STATES=PENDING|{'committed','rolled_back','not_applied'}
_UNSET=object()


class LanguageIO:
    def __init__(self,*,backend=None,close_desktop=None,available=None):
        self.available=platform.system()=='Darwin' if available is None else available
        self._backend=backend;self.close_desktop=close_desktop or (lambda:False)
        self.domain=backend.domain if backend else DOMAIN
    def backend(self):
        if not self.available:raise ValueError('此平台请在 Claude / 系统应用语言设置中调整；没有改写系统语言')
        if self._backend is None:self._backend=ClaudePreferences()
        return self._backend
    def actor(self):return str(os.geteuid()) if hasattr(os,'geteuid') else os.getlogin()
    def snapshot(self):return validate_snapshot(self.backend().read())
    def set_host(self,*args):return self.backend().set_host(*args)


class LanguageRepair:
    def __init__(self,store,io,*,root=None,transaction_lock=None,clock=None):
        import time
        self.store,self.io=store,io;self.root=Path(root) if root is not None else store.root/'client-language'
        self.locker=ConfigRemedies(self.root,self.root);self.locker.backups=self.root
        self.transaction_lock=transaction_lock or nullcontext;self.clock=clock or time.monotonic
        self.plans={};self.restores={}

    def _record(self):
        import json
        raw=read(self.root/'latest.private.json')
        if raw is None:return None
        index=json.loads(raw);ident=index.get('id') if isinstance(index,dict) else None
        if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('语言恢复索引无法读取')
        value=json.loads(read(self.root/ident/'record.private.json') or b'null')
        if (not isinstance(value,dict) or value.get('id')!=ident or type(value.get('version')) is not int or value['version']!=1
            or not isinstance(value.get('state'),str) or value['state'] not in STATES or value.get('domain')!=self.io.domain
            or not isinstance(value.get('owner'),str) or not value['owner']):raise ValueError('语言恢复记录无法核对，保留备份')
        validate_snapshot(value.get('before'));validate_snapshot(value.get('after'))
        original=read(self.root/ident/'before.private.json')
        if original is None or digest(original)!=value.get('before_hash') or json.loads(original)!=value['before']:
            raise ValueError('语言原值备份校验失败，没有使用未知原值')
        return value

    def _save(self,record,state):
        record['state']=state;record['updated_at']=datetime.now(timezone.utc).isoformat()
        path=self.root/record['id']/'record.private.json';_replace(path,encoded(record),read(path))
        append_event(self.root/'events',{'at':record['updated_at'],'kind':state,'transaction':record['id'],'text':'应用语言操作阶段：'+state})

    def status(self):
        base={'supported':self.io.available}
        try:
            record=self._record()
            if not record:return {**base,'state':'not_configured','can_restore':False,'reason':'尚无应用语言修改记录；按明确选择的目标处理。'}
            return {**base,'state':record['state'],'can_restore':record['state'] not in ('rolled_back','not_applied'),
                'backup_path':str(self.root/record['id']),'reason':'上次语言操作尚未完成，请先预览恢复，原值已保留。' if record['state'] in PENDING
                else '应用专用语言偏好已读回；实际界面语言需重开 Claude 后确认。' if record['state']=='committed'
                else '原来的应用语言键已处理；原来缺省的键继续使用当前系统回退语言。'}
        except (OSError,ValueError,RuntimeError,TypeError):
            return {**base,'state':'invalid','can_restore':False,'backup_path':str(self.root),'reason':'语言恢复记录无法核对，请保留原备份并手动处理。'}

    def _fresh(self,report):
        from .regions import PARTIAL,region_finding
        from .model import Status
        settings=self.store.settings()
        if (not settings.get('environment_confirmed') or not SolutionPlans._current(report)
            or report.get('environment',{}).get('fingerprint')!=fingerprint(settings)
            or not any(f['id']=='target.region' and f['status']=='pass' for f in report.get('findings',[]))):
            raise ValueError('先按当前目标完成新检测，并确认官方地区条件，再预览应用语言')
        if not settings.get('usage_country') or settings['usage_country'] in PARTIAL or region_finding([],settings).status==Status.FAIL:
            raise ValueError('实际地区条件尚未通过，应用语言设置不能改变服务使用资格')
        target=settings.get('language','').replace('_','-')
        if not target or settings.get('usage') not in ('desktop','both'):raise ValueError('先在桌面用途的检测目标中明确填写期望语言；没有替你选择英语')
        language_array([target])
        return settings,target

    def prepare(self,report):
        try:
            settings,target=self._fresh(report);previous=self._record()
            if previous and previous['state'] in PENDING:raise ValueError('上次语言操作未完成，请先恢复，没有覆盖原记录')
            if previous and previous['owner']!=self.io.actor():raise ValueError('语言记录属于另一用户，请由原用户核对')
            before=self.io.snapshot()
            if before['forced']:raise ValueError('Claude 语言由管理策略强制设置，请联系管理方，未覆盖')
            after={'any':{'present':True,'value':[target]},'current':{'present':True,'value':[target]} if before['current']['present'] else before['current'],
                   'effective':{'present':True,'value':[target]},'forced':False}
            if before==after:return {'state':'guided','reason':'应用语言偏好已符合目标，无需重复改写；实际界面请在 Claude 中确认。'}
            self._fresh(report);token=secrets.token_urlsafe(20)
            self.plans={token:{'deadline':self.clock()+90,'report':{k:report[k] for k in ('created_at','mode','diagnosis')},
                'report_id':report.get('report_id'),'fingerprint':fingerprint(settings),'previous':previous,'before':before,'after':after,'id':secrets.token_hex(16)}}
            return {'state':'planned','plan_id':token,'effects':[
                '先请求正常退出已识别的 Claude 桌面，请保存工作；退出未确认就停止，不强制退出、不交换账号资料。',
                '为当前用户的 Claude 应用专用 AppleLanguages 保存带类型的原值、缺省状态与恢复记录。',
                '只将该应用的语言列表设为 '+target+'；原有 ByHost 键一并核对，原来缺省的 ByHost 键不创建。',
                '不修改全局语言、系统地区格式或时区；不覆盖管理策略，保留其他应用偏好。',
                '逐项写入并读回应用解析后的偏好；失败后按原值恢复，异常或中断时保留恢复入口。',
                '完成后自动复检，暂不重开 Claude；偏好写入不能证明应用支持该语言或实际界面已切换。'],
                'reason':'只处理已明确选择的应用语言；请核对影响后确认。'}
        except (OSError,ValueError,RuntimeError) as error:
            return {'state':'guided','reason':str(error)[:260],'manual':['macOS 可在系统设置 → 通用 → 语言与地区 → 应用程序中为 Claude 选择语言；Windows 请在 Claude 实际支持的设置中确认。']}

    def apply(self,token,confirmed=False,current_report=_UNSET):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if (not plan or self.clock()>plan['deadline'] or not SolutionPlans._current(plan['report'])
            or plan['fingerprint']!=fingerprint(self.store.settings())):return {'state':'retest_required','reason':'语言方案或检测已过期，请重新检测并预览'}
        if current_report is not _UNSET:
            try:self._fresh(current_report)
            except (ValueError,OSError,RuntimeError):return {'state':'retest_required','reason':'本轮最新检测未满足应用语言设置条件，请重新检测并预览'}
            if not plan['report_id'] or current_report.get('report_id')!=plan['report_id']:
                return {'state':'retest_required','reason':'本机检测已更新，旧语言方案不再执行，请按最新结果重新预览'}
        with self.transaction_lock(),self.locker._lock():
            if self._record()!=plan['previous'] or self.io.snapshot()!=plan['before']:
                return {'state':'retest_required','reason':'应用语言或恢复记录已改变，没有覆盖'}
            self.plans.pop(token);directory=self.root/plan['id'];_safe(directory).mkdir(mode=0o700,parents=True,exist_ok=False)
            raw=encoded(plan['before']);_replace(directory/'before.private.json',raw,None)
            record={'version':1,'id':plan['id'],'domain':self.io.domain,'owner':self.io.actor(),'before':plan['before'],
                    'after':plan['after'],'before_hash':digest(raw),'state':'prepared'}
            self._save(record,'prepared');_replace(self.root/'latest.private.json',encoded({'id':record['id']}),read(self.root/'latest.private.json'))
            try:
                if self.io.close_desktop() is not True:
                    self._save(record,'not_applied');return {'state':'guided','reason':'Claude 正常退出未确认，没有改写应用语言'}
                if (self.clock()>plan['deadline'] or not SolutionPlans._current(plan['report'])
                    or self.io.snapshot()!=plan['before']):raise ValueError('正常退出期间方案过期或应用偏好改变，没有写入新语言')
                for host in HOSTS:
                    if record['before'][host]!=record['after'][host]:
                        self._save(record,'writing');self.io.set_host(host,record['after'][host],record['before'][host])
                if self.io.snapshot()!=record['after']:raise ValueError('应用语言解析后的偏好与方案不一致')
                self._save(record,'committed')
                return {'state':'completed','needs_retest':True,'reason':'Claude 专用语言偏好已独立读回；现在复检，实际界面仍需在 Claude 中确认。'}
            except (OSError,ValueError,RuntimeError) as error:
                recovered=self._restore(record)
                return {'state':'partial','needs_retest':True,'recovery':recovered,'reason':str(error)[:240]+' 原值与恢复记录保留。'}

    def _restore(self,record):
        self._save(record,'rolling_back')
        try:
            current=self.io.snapshot()
            if current['forced']:raise ValueError('应用语言现在由管理策略控制，未尝试覆盖')
            if any(current[h] not in (record['before'][h],record['after'][h]) for h in HOSTS):
                raise ValueError('应用语言有后续修改，没有覆盖；保留原值供手动核对')
            for host in HOSTS:
                if current[host]!=record['before'][host]:self.io.set_host(host,record['before'][host],current[host])
            actual=self.io.snapshot()
            if any(actual[h]!=record['before'][h] for h in HOSTS):raise ValueError('原应用语言键读回不一致')
            self._save(record,'rolled_back')
            return {'state':'completed','reason':'已恢复原应用语言键及缺省状态；系统回退语言按当前系统设置解析。'}
        except (OSError,ValueError,RuntimeError) as error:
            self._save(record,'partial');return {'state':'partial','reason':str(error)[:240]}

    def prepare_restore(self):
        try:
            record=self._record()
            if not record or record['state'] in ('rolled_back','not_applied'):raise ValueError('没有待恢复的应用语言修改')
            if record['owner']!=self.io.actor():raise ValueError('语言恢复记录属于另一用户，请由原用户核对')
            current=self.io.snapshot()
            if current['forced'] or any(current[h] not in (record['before'][h],record['after'][h]) for h in HOSTS):
                raise ValueError('应用语言受管理或存在后续修改，请保留备份并手动核对')
            token=secrets.token_urlsafe(20);self.restores={token:{'record':record,'current':current,'deadline':self.clock()+90}}
            return {'state':'planned','plan_id':token,'effects':['先正常退出已识别的 Claude，不强制退出，不重开或交换账号资料。',
                '只恢复本次 Claude 应用语言键的带类型原值；原来不存在的键删除，其他偏好及全局语言保留。',
                '恢复后同步、独立读回并复检；原副本与日志保留。'],'reason':'恢复范围只覆盖本次应用语言键。'}
        except (OSError,ValueError,RuntimeError) as error:return {'state':'guided','reason':str(error)[:260]}

    def restore(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.restores.get(token) if isinstance(token,str) else None
        if not plan or self.clock()>plan['deadline']:return {'state':'retest_required','reason':'语言恢复方案已过期，请重新预览'}
        with self.transaction_lock(),self.locker._lock():
            if self._record()!=plan['record'] or self.io.snapshot()!=plan['current']:
                return {'state':'retest_required','reason':'应用语言或恢复记录在预览后改变，没有覆盖'}
            if self.io.close_desktop() is not True:return {'state':'guided','reason':'Claude 正常退出未确认，没有恢复应用语言'}
            if self.clock()>plan['deadline']:return {'state':'retest_required','reason':'等待退出期间恢复方案已过期，请重新预览'}
            self.restores.pop(token)
            return {**self._restore(plan['record']),'needs_retest':True}
