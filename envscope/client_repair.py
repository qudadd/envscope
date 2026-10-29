"""Reviewed native proxy startup and durable Clash Verge TUN preference repair."""
from datetime import datetime,timezone
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import time

from .client_apps import AppLifecycle,discover_apps,file_hash
from .client_config import tun_model,update_tun,validate_model
from .discovery import config_directories
from .event_log import append_event
from .local_controller import LocalController,from_config
from .model import Finding,Status
from .regions import PARTIAL,region_finding
from .remedies import ConfigRemedies,SolutionPlans,_replace,_safe
from .routing import read
from .routing_config import load_yaml
from .target_environment import build_findings,fingerprint

PENDING={'prepared','stopping','writing','starting','rolling_back','partial'}
STATES=PENDING|{'committed','rolled_back','not_applied'}
_UNSET=object()


def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,allow_nan=False,separators=(',',':')).encode()


def planned_controller(config,system):
    """Planning does not require an offline Unix socket to exist.

    Actual requests still validate socket ownership and directories. No token is
    sent during this inspection, and no alternate endpoint is tried on failure.
    """
    unix=config.get('external-controller-unix')
    if system=='Darwin' and unix:
        if not isinstance(unix,str) or not Path(unix).is_absolute() or len(unix)>1000 or any(ord(c)<32 for c in unix):
            raise ValueError('本机内核 Unix 接口格式无法核对')
        return LocalController(unix=unix,secret=config.get('secret','') or '')
    return from_config(config,system)


class NativeClientIO:
    def __init__(self,home=None,system=None,environ=None,apps=None,life=None,stop_desktop=None,inventory=None,facts=None):
        self.home=Path(home or Path.home()).resolve();self.system=system or platform.system()
        self.environ=os.environ if environ is None else environ
        self.apps=apps or (lambda:discover_apps(self.home,self.system,self.environ))
        self.life=life or AppLifecycle(self.home,self.system)
        self.stop_desktop=stop_desktop
        from .inventory import collect
        from .network_facts import bounded_facts
        self.inventory=inventory or collect;self.facts=facts or bounded_facts

    def actor(self):return self.life.ps.Process().username()
    def directories(self):return config_directories(self.home,self.system,self.environ)
    def snapshot(self,app):return self.life.snapshot(app)
    def stop(self,app,allow_force=False):return self.life.stop(app,allow_force)
    def start(self,app):return self.life.start(app)
    def close_desktop(self):
        if self.stop_desktop is None:raise ValueError('缺少 Claude 正常退出接口，未重启代理')
        return self.stop_desktop() is True

    def context(self,app):
        if app['mode']!='clash-verge':raise ValueError('此客户端的 TUN 开关需在原客户端确认，本功能可单独启动它')
        choices=[p for p in self.directories() if read(p/'verge.yaml') is not None]
        if len(choices)!=1:raise ValueError('未找到唯一的 Clash Verge 偏好目录；先打开一次客户端，多个目录时先整理')
        directory=choices[0];raw=read(directory/'verge.yaml');model=tun_model(raw)
        runtime=read(directory/'clash-verge.yaml')
        _,config=load_yaml(runtime)
        controller=planned_controller(config,self.system)
        profiles=read(directory/'profiles.yaml')
        return {'directory':str(directory),'raw':raw,'model':model,'controller':controller.identity,
                'guards':{'profiles.yaml':digest(profiles) if profiles is not None else None}}

    def observe(self,app,settings,context=None):
        state=self.snapshot(app)
        if state['unreadable'] or not state['processes']:
            return {'ready':False,'reason':'尚未读回所选客户端的当前用户进程'}
        if context is None:return {'ready':True,'scope':'selected-application-process','reason':'所选客户端进程已读回；连接另行复检'}
        current=self.context(app)
        if current['directory']!=context['directory'] or current['controller']!=context['controller']:
            raise ValueError('客户端重新生成了内核接口；未向不同接口发送旧认证，请复检后重新预览')
        if current['model']!={'present':True,'value':True}:
            return {'ready':False,'reason':'TUN 偏好未保持已批准的开启值'}
        _,config=load_yaml(read(Path(context['directory'])/'clash-verge.yaml'))
        controller=from_config(config,self.system)
        version=controller.request('/version');live=controller.request('/configs')
        if version.get('meta') is not True or not isinstance(live.get('tun'),dict) or live['tun'].get('enable') is not True:
            return {'ready':False,'reason':'内核尚未确认 TUN 开启；服务模式或系统授权可能仍待处理'}
        inventory=self.inventory();facts=self.facts()
        findings=[Finding('system.inventory','系统资料',Status.UNKNOWN,'仅供选路核对','native-client',[inventory]),
                  Finding('extra.dns_resolution','目标解析',Status.UNKNOWN,'仅供选路核对','native-client',facts.get('dns',[])),
                  Finding('extra.target_route','系统选路',Status.UNKNOWN,'仅供选路核对','native-client',facts.get('routes',[]))]
        route=next((f for f in build_findings(findings,settings) if f.id=='target.tun_route'),None)
        return {'ready':bool(route and route.status==Status.PASS),'scope':'gui-preference-core-tun-and-sampled-target-routes',
                'reason':route.summary if route else '当前目标没有可验证的 TUN 选路范围',
                'note':'只覆盖已选用途的解析地址与地址族抽样；不是 Claude 进程全流量证明。'}


class ClientRepair:
    def __init__(self,store,io,*,root=None,clock=None,sleeper=None,transaction_lock=None):
        self.store,self.io=store,io;self.root=Path(root) if root is not None else store.root/'client-repair'
        self.locker=ConfigRemedies(self.root,self.root);self.locker.backups=self.root
        self.clock=clock or time.monotonic;self.sleep=sleeper or time.sleep;self.plans={};self.restore_plans={}
        self.transaction_lock=transaction_lock or nullcontext

    def _app(self,ident,approved=None):
        choices=self.io.apps()
        if ident is None:
            mode=self.store.settings().get('client','auto')
            choices=[a for a in choices if mode=='auto' or a['mode']==mode]
            if len(choices)!=1:raise ValueError('请选择实际使用的已安装代理客户端；没有猜选多个程序')
            app=choices[0]
        else:
            found=[a for a in choices if a['id']==ident]
            if len(found)!=1:raise ValueError('所选客户端已变化，请重新读取')
            app=found[0]
        app={**app,'sha256':file_hash(app['path'])}
        if approved is not None and any(app.get(k)!=approved.get(k) for k in ('id','mode','path','bundle','sha256')):
            raise ValueError('代理客户端的位置或文件已更新，请重新审核，未运行新的文件')
        return app

    def _record(self):
        raw=read(self.root/'latest.private.json')
        if raw is None:return None
        index=json.loads(raw);ident=index.get('id') if isinstance(index,dict) else None
        if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('客户端修复索引无法核对')
        value=json.loads(read(self.root/ident/'record.private.json') or b'null')
        if (not isinstance(value,dict) or value.get('id')!=ident or type(value.get('version')) is not int or value['version']!=1
                or not isinstance(value.get('state'),str) or value['state'] not in STATES or not isinstance(value.get('app'),dict)
                or type(value.get('tun')) is not bool or type(value.get('was_running')) is not bool or type(value.get('restart')) is not bool
                or not isinstance(value.get('owner'),str) or not value['owner']):
            raise ValueError('客户端恢复记录损坏，请保留备份并手动核对')
        app=value['app']
        if (not all(isinstance(app.get(k),str) and 0<len(app[k])<=32768 for k in ('id','mode','label','path','sha256'))
                or not Path(app['path']).is_absolute() or not re.fullmatch('[a-f0-9]{64}',app['sha256'])
                or app['mode'] not in ('clash-verge','flclash','shadowrocket','clashx','surge','wireguard','other')):
            raise ValueError('客户端原程序记录无法核对，保留备份')
        if value['tun']:
            directory=value.get('directory')
            if not isinstance(directory,str) or not Path(directory).is_absolute() or Path(directory) not in self.io.directories():
                raise ValueError('客户端恢复目录不在已识别范围内')
            validate_model(value.get('before'));validate_model(value.get('after'))
            backup=read(self.root/ident/'before.private.bin')
            if backup is None or digest(backup)!=value.get('before_hash') or tun_model(backup)!=value['before']:
                raise ValueError('客户端原配置备份校验失败，未以未知原值覆盖')
        return value

    def _save(self,record,state):
        record['state']=state;record['updated_at']=datetime.now(timezone.utc).isoformat()
        path=self.root/record['id']/'record.private.json'
        _replace(path,encoded(record),read(path))
        append_event(self.root/'events',{'at':record['updated_at'],'kind':state,'transaction':record['id'],
                                        'text':'客户端修复阶段：'+state,'client':record['app']['label']})

    def status(self):
        try:
            record=self._record()
            if not record:return {'state':'not_configured','can_restore':False,'reason':'尚无客户端修改记录'}
            return {'state':record['state'],'client':record['app']['label'],'can_restore':record['state'] not in ('rolled_back','not_applied'),
                    'backup_path':str(self.root/record['id']),
                    'reason':'上次操作尚未完成；先预览恢复，原副本已保留。' if record['state'] in PENDING else
                             '上次 TUN 偏好与所列选路已核对；当前连接以重新检测为准。' if record['state']=='committed' and record['tun'] else
                             '所选客户端进程已读回；当前连接仍需重新检测。' if record['state']=='committed' else
                             '原偏好及所选客户端状态已处理；连接仍需复检。'}
        except (OSError,ValueError,TypeError,RuntimeError):
            return {'state':'invalid','can_restore':False,'backup_path':str(self.root),'reason':'恢复记录无法安全读取，保留备份，请手动核对客户端偏好。'}

    def options(self):
        return {'state':'completed','apps':[{**app,'tun_supported':app['mode']=='clash-verge'} for app in self.io.apps()],'recovery':self.status(),
                'note':'程序按安装位置识别；修改前固定文件摘要。sing-box 无统一图形入口，请按现有服务方式启动，不猜测命令。'}

    def _fresh(self,report):
        settings=self.store.settings()
        if (not settings.get('environment_confirmed') or not SolutionPlans._current(report)
                or report.get('environment',{}).get('fingerprint')!=fingerprint(settings)):
            raise ValueError('先按当前目标完成一次新检测，再预览客户端修复')
        if (not settings.get('usage_country') or settings['usage_country'] in PARTIAL
                or region_finding([],settings).status==Status.FAIL
                or not any(f['id']=='target.region' and f['status']=='pass' for f in report.get('findings',[]))):
            raise ValueError('实际地区未确认或官方地区条件未通过，更改代理不能改变使用资格')
        return settings

    def prepare(self,report,app_id=None,*,tun=False,restart=False,allow_force=False,start_if_tun_manual=False):
        if any(type(v) is not bool for v in (tun,restart,allow_force,start_if_tun_manual)):raise ValueError('TUN、重开与强制退出选项需要明确的布尔值')
        try:
            settings=self._fresh(report);previous=self._record()
            if previous and previous['state'] in PENDING:raise ValueError('上次客户端操作未完成，先预览恢复，未覆盖原记录')
            if previous and previous['owner']!=self.io.actor():raise ValueError('现有客户端修复记录属于另一用户，请保留并由原用户核对')
            app=self._app(app_id)
            if settings['client'] not in ('auto',app['mode']):raise ValueError('所选程序与已确认客户端目标不同，请先调整目标并复检')
            if tun and settings['connection_mode']!='tun':raise ValueError('当前目标不是 TUN 连接，不生成 TUN 改写')
            manual=[]
            if tun and app['mode']!='clash-verge' and start_if_tun_manual:
                tun=False
                manual=[app['label']+' 的 TUN 开关需在原客户端开启并完成系统授权；本次只启动客户端，不改写其偏好，之后自动复检。']
            state=self.io.snapshot(app)
            if state['unreadable']:raise ValueError('所选客户端进程归属无法读取，未生成退出方案')
            if state['processes'] and not tun and not restart:
                return {'state':'guided','reason':'所选客户端已运行，无需重复启动；连接异常时可明确选择重开后重新预览。','manual':manual}
            context=self.io.context(app) if tun else None
            self._fresh(report)
            token=secrets.token_urlsafe(20)
            self.plans={token:{'deadline':self.clock()+90,'settings':fingerprint(settings),'app':app,'state':state,
                'previous':previous,'context':context,'tun':tun,'restart':tun or restart,'allow_force':allow_force,
                'report':{k:report[k] for k in ('created_at','mode','diagnosis')},'report_id':report.get('report_id'),'id':secrets.token_hex(16)}}
            effects=['先请求正常退出已识别的 Claude 桌面；请保存工作。账号资料不交换、不调用登出，完成复检前不自动重开 Claude。',
                     '只处理所选程序：'+app['label']+'（'+app['path']+'）；启动前再次核对位置和文件摘要。']
            if tun:
                effects+=['保存 Clash Verge 原偏好文件与事务记录，核对配置后退出所选客户端，只将 enable_tun_mode 明确设为 true；保留其他偏好、订阅、节点及脚本。',
                          '退出及重开代理会短暂中断其他应用的连接。正常退出未确认时停止，不在运行中的 GUI 上覆盖偏好。',
                          '重开所选客户端，读回偏好、内核 TUN 与目标域名抽样选路；系统服务或驱动需要授权时，由原客户端向你申请。',
                          '验证失败时尝试恢复本次 TUN 偏好；不能核实退出或恢复时保留所有副本，提供恢复入口。']
            elif restart:effects.append('先正常退出再重开所选客户端，会短暂中断其他应用连接；读回当前用户进程，连接与 TUN 另行复检。')
            else:effects.append('只在所选程序尚未运行时提交启动请求，再读取当前用户进程；启动不等于连接或 TUN 已通过。')
            if allow_force:effects.append('已明确允许本次强制退出所选代理客户端：正常退出失败后终止，2 秒未退出再强制结束；未保存的代理配置可能丢失。不会强制退出 Claude。')
            return {'state':'planned','plan_id':token,'effects':effects,'client':app['label'],'manual':manual,
                    'reason':'审核具体程序与退出范围后确认；客户端启动和 TUN 读回均须独立验证。'}
        except (OSError,ValueError,RuntimeError) as error:
            return {'state':'guided','reason':str(error)[:260],'manual':['先在原客户端核对节点、服务模式及系统授权；正常退出受阻时从系统托盘退出后重新预览。']}

    def _wait(self,app,settings,context):
        deadline=self.clock()+45;last={'ready':False,'reason':'客户端尚未返回可核实状态'}
        while self.clock()<deadline:
            try:last=self.io.observe(app,settings,context)
            except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:last={'ready':False,'reason':str(error)[:240]}
            if last.get('ready') is True:return last
            self.sleep(1)
        return last

    def apply(self,token,confirmed=False,current_report=_UNSET):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if (not plan or self.clock()>plan['deadline'] or not SolutionPlans._current(plan['report'])
                or plan['settings']!=fingerprint(self.store.settings())):
            return {'state':'retest_required','reason':'目标、检测或方案已过期，请重新检测并预览'}
        if current_report is not _UNSET:
            try:self._fresh(current_report)
            except (ValueError,OSError,RuntimeError):return {'state':'retest_required','reason':'本轮最新检测未满足客户端修复条件，请重新检测并预览'}
            if not plan['report_id'] or current_report.get('report_id')!=plan['report_id']:
                return {'state':'retest_required','reason':'本机检测已更新，旧客户端方案不再执行，请按最新结果重新预览'}
        with self.transaction_lock(),self.locker._lock():
            if self._record()!=plan['previous']:return {'state':'retest_required','reason':'客户端恢复记录已改变，未覆盖'}
            app=self._app(plan['app']['id'],plan['app']);state=self.io.snapshot(app)
            if state!=plan['state']:return {'state':'retest_required','reason':'客户端进程在预览后改变，请重新预览'}
            context=self.io.context(app) if plan['tun'] else None
            if context!=plan['context']:return {'state':'retest_required','reason':'客户端配置或内核接口在预览后改变，未写入'}
            self.plans.pop(token)
            record={'version':1,'id':plan['id'],'owner':self.io.actor(),'app':app,'tun':plan['tun'],'restart':plan['restart'],
                    'was_running':bool(state['processes']),'before':context['model'] if context else None,
                    'after':{'present':True,'value':True} if context else None,'directory':context['directory'] if context else None,
                    'before_hash':digest(context['raw']) if context else None,'state':'prepared'}
            directory=self.root/record['id'];_safe(directory).mkdir(mode=0o700,parents=True,exist_ok=False)
            if context:_replace(directory/'before.private.bin',context['raw'],None)
            self._save(record,'prepared')
            _replace(self.root/'latest.private.json',encoded({'id':record['id']}),read(self.root/'latest.private.json'))
            try:
                if not self.io.close_desktop():
                    self._save(record,'not_applied')
                    return {'state':'guided','reason':'Claude 正常退出尚未确认；未停止代理或写入 TUN，请先保存并关闭 Claude。'}
                if self.clock()>plan['deadline'] or not SolutionPlans._current(plan['report']):
                    self._save(record,'not_applied')
                    return {'state':'retest_required','needs_retest':True,'reason':'等待 Claude 正常退出期间检测已过期，未停止代理或修改 TUN，请重新检测。'}
                if plan['restart']:
                    self._save(record,'stopping');stopped=self.io.stop(app,plan['allow_force'])
                    if stopped.get('stopped') is not True:
                        self._save(record,'not_applied')
                        return {'state':'guided','reason':'所选代理客户端未退出，未改写配置；请从托盘退出后重新预览，或在新方案中明确选择本次允许强制退出。'}
                if context:
                    # GUI exit can flush its own preferences. Preserve such edits
                    # instead of restoring a stale full file over them.
                    current=self.io.context(app)
                    if current!=context:raise ValueError('客户端退出时保存了新的配置，已保留这些修改；本次未覆盖，请复检后重新预览')
                    if self.clock()>plan['deadline'] or not SolutionPlans._current(plan['report']):raise ValueError('退出期间检测已过期，本次不写入新的 TUN 配置')
                    self._save(record,'writing')
                    path=Path(context['directory'])/'verge.yaml'
                    _replace(path,update_tun(context['raw'],record['after']),context['raw'])
                    if tun_model(read(path))!=record['after']:raise ValueError('TUN 偏好写入读回不一致')
                if self.clock()>plan['deadline'] or not SolutionPlans._current(plan['report']):raise ValueError('客户端退出期间方案已过期，不继续新的启动，按记录恢复')
                self._save(record,'starting');self.io.start(app)
                observed=self._wait(app,self.store.settings(),context)
                if observed.get('ready') is not True:raise ValueError(observed.get('reason','客户端尚未完成验证'))
                self._app(app['id'],app);self._save(record,'committed')
                return {'state':'completed','needs_retest':True,'scope':observed.get('scope'),'reason':observed['reason']+'；现在重新检测整个目标环境。'}
            except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
                restored=self._restore(record,plan['allow_force'])
                return {'state':'partial','needs_retest':True,'recovery':restored,'reason':str(error)[:240]+' 原备份与恢复记录保留，请查看客户端恢复状态。'}

    def _restore(self,record,allow_force=False):
        self._save(record,'rolling_back')
        try:
            app=self._app(record['app']['id'],record['app'])
            if record['tun']:
                path=Path(record['directory'])/'verge.yaml';raw=read(path);current=tun_model(raw)
                if current not in (record['before'],record['after']):raise ValueError('TUN 偏好存在后续修改，没有覆盖')
                if current!=record['before']:
                    if self.io.stop(app,allow_force).get('stopped') is not True:raise ValueError('客户端退出未确认，未覆盖运行中的偏好')
                    raw=read(path)
                    if tun_model(raw)!=record['after']:raise ValueError('退出期间 TUN 偏好改变，没有覆盖')
                    _replace(path,update_tun(raw,record['before']),raw)
                    if tun_model(read(path))!=record['before']:raise ValueError('原 TUN 偏好读回失败')
            if record['was_running']:
                self.io.start(app)
                if self._wait(app,self.store.settings(),None).get('ready') is not True:raise ValueError('原客户端启动状态未确认')
            elif self.io.snapshot(app)['processes']:
                if self.io.stop(app,allow_force).get('stopped') is not True:raise ValueError('原先未运行的客户端尚未退出')
            self._save(record,'rolled_back')
            return {'state':'completed','reason':'保存的 TUN 偏好及客户端启动状态已恢复；原内核和网络状态仍须复检。'}
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
            self._save(record,'partial')
            return {'state':'partial','reason':str(error)[:240]}

    def prepare_restore(self,*,allow_force=False):
        if type(allow_force) is not bool:raise ValueError('强制退出需要明确选择')
        try:
            record=self._record()
            if not record or record['state'] in ('rolled_back','not_applied'):raise ValueError('没有待恢复的客户端修改')
            if record['owner']!=self.io.actor():raise ValueError('恢复记录属于另一用户，请由原用户核对')
            app=self._app(record['app']['id'],record['app']);snapshot=self.io.snapshot(app)
            if snapshot['unreadable']:raise ValueError('客户端进程归属无法读取')
            raw=read(Path(record['directory'])/'verge.yaml') if record['tun'] else None
            if record['tun'] and tun_model(raw) not in (record['before'],record['after']):raise ValueError('TUN 偏好已在之后改变，保留备份并在客户端手动核对')
            token=secrets.token_urlsafe(20)
            self.restore_plans={token:{'record':record,'snapshot':snapshot,'raw':raw,'deadline':self.clock()+90,'allow_force':allow_force}}
            effects=['先正常退出已识别的 Claude 桌面，不强制退出、不交换资料；不会自动重开 Claude。',
                     ('只恢复 '+app['label']+' 的本次 TUN 偏好，保留其他字段的后续修改，' if record['tun'] else '本次未改写 TUN，')+'并按原记录恢复客户端的启动 / 停止状态。',
                     '需要重启客户端时会短暂影响其他应用的连接；备份和日志保留，网络是否恢复另行复检。']
            if allow_force:effects.append('已明确允许本次恢复在正常退出失败后强制退出所选代理客户端，未保存内容可能丢失。')
            return {'state':'planned','plan_id':token,'effects':effects,'reason':'恢复只针对所列偏好和所选程序，不将进程状态当作网络证明。'}
        except (OSError,ValueError,RuntimeError) as error:return {'state':'guided','reason':str(error)[:260]}

    def restore(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.restore_plans.get(token) if isinstance(token,str) else None
        if not plan or self.clock()>plan['deadline']:return {'state':'retest_required','reason':'恢复方案已过期，请重新预览'}
        with self.transaction_lock(),self.locker._lock():
            if self._record()!=plan['record']:return {'state':'retest_required','reason':'恢复记录已变化，请重新预览'}
            record=plan['record'];app=self._app(record['app']['id'],record['app'])
            raw=read(Path(record['directory'])/'verge.yaml') if record['tun'] else None
            if raw!=plan['raw'] or self.io.snapshot(app)!=plan['snapshot']:return {'state':'retest_required','reason':'恢复现场已变化，没有覆盖后续修改'}
            if not self.io.close_desktop():return {'state':'guided','reason':'Claude 正常退出尚未确认，没有继续恢复'}
            self.restore_plans.pop(token)
            return {**self._restore(record,plan['allow_force']),'needs_retest':True}
