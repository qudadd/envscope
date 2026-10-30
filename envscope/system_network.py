"""Reviewed OS network operations. A command return never proves connectivity.

Platform executors keep privileged receipts outside user-writable directories.
The coordinator and all tests can inject an executor; diagnostics never write.
"""
import hashlib
import plistlib
import platform
import re
import secrets
import subprocess
import time

from .model import Status
from .regions import PARTIAL,region_finding
from .remedies import SolutionPlans
from .target_environment import fingerprint


IDENTIFIER=re.compile(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z')
PENDING={'prepared','applying','partial'}


def signature(value):
    return hashlib.sha256(plistlib.dumps(value,sort_keys=True)).hexdigest()


def validate_snapshot(value):
    if (not isinstance(value,dict) or type(value.get('format')) is not int or value['format']!=1
            or not isinstance(value.get('adapters'),list) or len(value['adapters'])>256):
        raise ValueError('系统网络信息格式无效，没有生成修改方案。')
    owner=value.get('owner')
    if not (type(owner) is int and owner>=0 or isinstance(owner,str) and re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+',owner)):
        raise ValueError('未核实当前用户的网络操作归属。')
    found=set()
    for row in value['adapters']:
        if (not isinstance(row,dict) or not isinstance(row.get('id'),str) or not IDENTIFIER.fullmatch(row['id'])
                or row['id'].lower() in found or not isinstance(row.get('name'),str) or not 0<len(row['name'])<=512
                or type(row.get('active')) is not bool or type(row.get('ipv6_enabled')) is not bool
                or not isinstance(row.get('config'),dict)):
            raise ValueError('网络接口的标识、状态或原配置无法核实，没有覆盖未知值。')
        found.add(row['id'].lower())
    # Plists preserve CFData and integer values in manual network configurations.
    try:size=len(plistlib.dumps(value,sort_keys=True))
    except (ValueError,TypeError,OverflowError):raise ValueError('网络原配置不能完整保留，未生成修改。') from None
    if size>2*1024**2:
        raise ValueError('网络配置超出审核范围，请在系统设置处理。')
    return value


def public_status(record):
    return {k:v for k,v in record.items() if k in ('id','state','release','dns_flush','reason','fixture')} | {
        'adapters':[{k:r.get(k) for k in ('id','name','ipv6_enabled')} for r in record.get('adapters',[])]}


def binding_view(snapshot,identifiers):
    return {r['id']:{k:r[k] for k in ('ipv6_enabled','config')} for r in snapshot['adapters'] if r['id'] in identifiers}


class UnavailableNetworkIO:
    supported=False
    def __init__(self,reason='系统网络修改支持 Windows 和 macOS；当前实例未连接系统执行器。'):
        self.reason=reason
    def snapshot(self):raise ValueError(self.reason)
    def status(self):return {'state':'unavailable','id':'','reason':self.reason}
    def execute(self,*args):raise ValueError(self.reason)


def native_network_io():
    if platform.system()=='Windows':
        from .system_network_windows import WindowsNetworkIO
        return WindowsNetworkIO()
    if platform.system()=='Darwin':
        from .system_network_macos import MacNetworkIO
        return MacNetworkIO()
    return UnavailableNetworkIO()


class SystemNetwork:
    def __init__(self,store,io):
        self.store,self.io=store,io
        self.plans={}

    def status(self):
        try:
            record=public_status(self.io.status())
            return {'supported':getattr(self.io,'supported',True),**record,
                    'can_restore':record.get('state') in PENDING|{'committed'} and bool(record.get('adapters') or record.get('state') in PENDING)}
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            return {'state':'unavailable','supported':getattr(self.io,'supported',True),
                    'reason':str(error)[:240],'can_restore':False}

    def options(self):
        try:
            snapshot=validate_snapshot(self.io.snapshot())
            record=self.io.status()
            return {'state':'completed','supported':True,
                    'adapters':[{k:row[k] for k in ('id','name','active','ipv6_enabled')} for row in snapshot['adapters']],
                    'recovery':public_status(record),'note':'仅按明确批准的接口修改 IPv6，DNS 操作只刷新缓存；不替换 DNS 服务器，不将配置读回当作流量证明。'}
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            return {'state':'guided','supported':getattr(self.io,'supported',True),'reason':str(error)[:240],
                    'manual':['在系统网络设置中核对当前使用的网络接口和 IPv6。权限不足时只为本次已审核的修改申请系统授权。']}

    def prepare(self,report,*,adapter_ids=None,flush_dns=False):
        if type(flush_dns) is not bool:raise ValueError('DNS 缓存选项需要明确的布尔值')
        settings=self.store.settings()
        if (not SolutionPlans._current(report) or not settings.get('environment_confirmed')
                or report.get('environment',{}).get('fingerprint')!=fingerprint(settings)):
            return {'state':'retest_required','reason':'先按当前目标完成检测，再预览系统网络修改。'}
        if (not settings.get('usage_country') or settings['usage_country'] in PARTIAL
                or region_finding([],settings).status==Status.FAIL
                or not any(f['id']=='target.region' and f['status']=='pass' for f in report.get('findings',[]))):
            return {'state':'blocked','reason':'实际地区未确认或官方地区条件不合格，未生成网络修改方案。'}
        record=self.io.status()
        if record.get('state') in PENDING:
            return {'state':'recovery_required','reason':'上次系统网络修改未完成，先预览恢复；原记录没有被覆盖。'}
        snapshot=validate_snapshot(self.io.snapshot())
        if adapter_ids is not None:
            if (not isinstance(adapter_ids,list) or any(not isinstance(v,str) for v in adapter_ids)
                    or len(set(adapter_ids))!=len(adapter_ids) or set(adapter_ids)-{r['id'] for r in snapshot['adapters']}):
                raise ValueError('请选择本次读取到的网络接口')
        else:
            adapter_ids=[r['id'] for r in snapshot['adapters'] if r['active'] and r['ipv6_enabled']]
        if adapter_ids and settings.get('ipv6_mode')!='disabled':
            return {'state':'guided','reason':'当前 IPv6 目标不是关闭。请先确认目标并复检；不会按上游默认行为关闭 IPv6。'}
        chosen=[r for r in snapshot['adapters'] if r['id'] in adapter_ids and r['ipv6_enabled']]
        if not chosen and not flush_dns:return {'state':'guided','reason':'所选接口已符合关闭目标，没有需要写入的配置。'}
        if not SolutionPlans._current(report):
            return {'state':'retest_required','reason':'读取接口期间检测结果已过期，没有生成修改；请重新检测。'}
        token=secrets.token_urlsafe(20)
        payload={'format':1,'nonce':secrets.token_hex(16),'owner':snapshot['owner'],
                 'expected_record':record.get('id',''),'adapters':chosen,'flush_dns':flush_dns}
        self.plans={token:{'deadline':time.monotonic()+90,'fingerprint':fingerprint(settings),
                           'snapshot':snapshot,'record':record,'payload':payload,
                           'report':{k:report[k] for k in ('created_at','mode','diagnosis')}}}
        effects=['为本次明确修改申请一次系统授权；所选接口的变化会影响使用它的其他应用。',
                 '先保存接口原配置和受保护的事务记录，修改前重新核对，修改后独立读回；失败停止并尝试恢复本次改动。']
        effects.extend('关闭 IPv6：'+r['name']+'（'+r['id']+'）' for r in chosen)
        if chosen:effects.append('保留 IPv4、地址和 DNS 服务器设置；Windows 若连带改变其他绑定，将停止并报告，避免覆盖无法归因的后续变化。')
        if flush_dns:effects.append('刷新本机 DNS 缓存；缓存内容不能撤销，后续查询会重新建立。不会更换 DNS 服务器；解析和连接另行复检。')
        return {'state':'planned','plan_id':token,'transaction_id':payload['nonce'],'effects':effects,
                'reason':'核对具体接口后确认；配置读回只证明所列设置，不证明 DNS 出口或全部流量。'}

    @staticmethod
    def _same_selected(snapshot,plan):
        current={r['id']:r for r in snapshot['adapters']}
        for before in plan['payload']['adapters']:
            after=current.get(before['id'])
            if not after or any(after[k]!=before[k] for k in ('ipv6_enabled','config','active')):return False
        return snapshot['owner']==plan['snapshot']['owner']

    def apply(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if (not plan or plan.get('restore') or time.monotonic()>plan['deadline']
                or not SolutionPlans._current(plan['report'])
                or plan['fingerprint']!=fingerprint(self.store.settings())):
            return {'state':'retest_required','reason':'目标或方案已经变化，请重新检测并预览。'}
        snapshot=validate_snapshot(self.io.snapshot())
        if not self._same_selected(snapshot,plan) or self.io.status()!=plan['record']:
            return {'state':'retest_required','reason':'接口、原配置或恢复记录在预览后改变，没有覆盖后续修改。'}
        if time.monotonic()>plan['deadline'] or not SolutionPlans._current(plan['report']):
            return {'state':'retest_required','reason':'核对期间方案或检测结果已过期，尚未修改；请重新检测。'}
        del self.plans[token]
        try:
            self.io.execute('apply',plan['payload'])
            status=self.io.status();observed=validate_snapshot(self.io.snapshot())
            rows={r['id']:r for r in observed['adapters']}
            verified=(status.get('id')==plan['payload']['nonce'] and status.get('state')=='committed'
                      and all(r['id'] in rows and rows[r['id']]['ipv6_enabled'] is False
                              and rows[r['id']]['config']==r['config'] for r in plan['payload']['adapters'])
                      and (not plan['payload']['flush_dns'] or status.get('dns_flush')=='completed'))
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            recovery=self.status()
            from .consent import operation_outcome
            return {'state':'partial','reason':str(error)[:240]+' 请查看恢复状态；原备份没有自动丢弃。',
                    'status':recovery,**operation_outcome(error)}
        return {'state':'completed' if verified else 'partial','status':public_status(status),'needs_retest':True,
                'transaction_id':plan['payload']['nonce'],'scope':'selected-network-settings',
                'reason':'所列网络设置已读回；现在复检解析、连接及出口。' if verified else '系统操作返回，但配置或缓存刷新尚未完整确认；请按恢复记录处理。'}

    def prepare_restore(self):
        record=self.io.status()
        if record.get('state') not in PENDING|{'committed'}:
            return {'state':'guided','reason':'没有可恢复的系统网络修改。'}
        snapshot=validate_snapshot(self.io.snapshot())
        if record.get('owner')!=snapshot['owner']:
            return {'state':'blocked','reason':'系统网络恢复记录属于另一用户，请由其本人或管理员处理。'}
        if not record.get('adapters') and record.get('state') not in PENDING:
            return {'state':'guided','reason':'上次仅刷新 DNS 缓存，没有可恢复的配置；缓存会随查询重新建立。'}
        current=binding_view(snapshot,{r['id'] for r in record.get('adapters',[])})
        if any(r['id'] not in current or current[r['id']]['config']!=r['config'] for r in record.get('adapters',[])):
            return {'state':'blocked','reason':'接口或其他网络配置已在之后改变，未生成覆盖方案。请对照备份在系统设置处理。'}
        token=secrets.token_urlsafe(20)
        self.plans={token:{'deadline':time.monotonic()+90,'restore':True,'record':record,'snapshot':snapshot}}
        return {'state':'planned','plan_id':token,
                'effects':['申请一次系统授权，只恢复最新事务中保留的网络接口原配置。',
                           '接口或配置出现其他变化时停止，保留全部备份。DNS 缓存内容不能回滚，完成后需复检。'],
                'reason':'恢复只使用受保护的原配置，不会继续尝试上次失败的新方案。'}

    def restore(self,token,confirmed=False):
        if confirmed is not True:return {'state':'confirmation_required'}
        plan=self.plans.get(token) if isinstance(token,str) else None
        if not plan or not plan.get('restore') or time.monotonic()>plan['deadline']:
            return {'state':'retest_required','reason':'恢复方案已过期，请重新预览。'}
        observed=validate_snapshot(self.io.snapshot());ids={r['id'] for r in plan['record'].get('adapters',[])}
        if (self.io.status()!=plan['record'] or observed['owner']!=plan['snapshot']['owner']
                or binding_view(observed,ids)!=binding_view(plan['snapshot'],ids)):
            return {'state':'retest_required','reason':'恢复现场发生变化，没有覆盖新的配置。'}
        del self.plans[token]
        try:
            self.io.execute('restore',{'format':1,'record_id':plan['record']['id'],'owner':plan['snapshot']['owner']})
            status=self.io.status();snapshot=validate_snapshot(self.io.snapshot())
            rows={r['id']:r for r in snapshot['adapters']}
            restored=(status.get('state')=='restored' and all(r['id'] in rows and
                      all(rows[r['id']][k]==r[k] for k in ('ipv6_enabled','config')) for r in plan['record'].get('adapters',[])))
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            from .consent import operation_outcome
            return {'state':'partial','reason':str(error)[:240]+' 恢复记录保留。','status':self.status(),**operation_outcome(error)}
        return {'state':'completed' if restored else 'partial','status':public_status(status),'needs_retest':True,
                'reason':'系统网络恢复已返回，请复检实际设置与连接。'}
