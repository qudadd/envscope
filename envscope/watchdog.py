"""Approved baseline recovery; no background elevation, installs or account writes."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import time
from urllib.parse import urlsplit

from .discovery import discover_proxies, safe_local_proxy
from .inventory import collect
from .region_profiles import profile
from .region_setup import current_region, discover_controller, set_system_value, _run
from .accounts import _safe_chain
from .transport import CurlTransport


def native_write(key, value, system=None, runner=_run):
    system=system or platform.system()
    if key=='timezone':
        # Fixed preset identifiers, without UAC / osascript dialogs in a background task.
        from .region_profiles import profiles
        if value not in {p['timezone'] for p in profiles(system)}:
            raise ValueError('时区不在批准的预设内')
        command=([str(Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/tzutil.exe'),'/s',value]
                 if system=='Windows' else ['/usr/sbin/systemsetup','-settimezone',value])
        if system not in ('Windows','Darwin') or runner(command,timeout=15).returncode:
            raise ValueError('后台没有修改时区的权限；请在持续维护页授权 macOS 系统时区守护，或在系统设置处理')
    else:
        set_system_value(system,key,value,runner)


def proxy_alive(url):
    parsed=urlsplit(safe_local_proxy(url) or '')
    if not parsed.hostname:return False
    try:
        with socket.create_connection((parsed.hostname,parsed.port),timeout=1):return True
    except OSError:return False


def proxy_works(url):
    r=CurlTransport(url).get('https://api.anthropic.com/v1/models')
    return r.status in (200,401) and r.tls_verified is True and not r.error


def proxy_apps(home=None,system=None,environ=None):
    home=Path(home or Path.home());system=system or platform.system();env=os.environ if environ is None else environ
    if system=='Windows':
        roots=[Path(env.get('LOCALAPPDATA') or home/'AppData/Local')/'Programs',Path(env.get('ProgramFiles') or 'C:/Program Files')]
        candidates=[(label,root/folder/exe) for root in roots for label,folder,exe in
                    [('Clash Verge Rev','Clash Verge','clash-verge.exe'),('Clash Verge Rev','clash-verge','clash-verge.exe'),
                     ('Mihomo Party','Mihomo Party','Mihomo Party.exe'),('Clash Nyanpasu','Clash Nyanpasu','Clash Nyanpasu.exe')]]
    elif system=='Darwin':
        candidates=[(name,root/(name+'.app')/'Contents/MacOS'/binary) for root in (Path('/Applications'),home/'Applications') for name,binary in
                    [('Clash Verge','clash-verge'),('Mihomo Party','Mihomo Party'),('Clash Nyanpasu','clash-nyanpasu')]]
    else:candidates=[]
    result=[]
    for label,path in candidates:
        try:
            _safe_chain(path)
            if not path.is_file():continue
            result.append({'id':hashlib.sha256(str(path).encode()).hexdigest()[:20],'label':label,'path':str(path)})
        except (OSError,ValueError,RuntimeError):continue
    return result


def executable_hash(path):
    file=Path(path);_safe_chain(file)
    if not file.is_file() or file.stat().st_size>500*1024*1024:raise ValueError('客户端文件不可用')
    digest=hashlib.sha256()
    with file.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def launch_proxy(client,system=None):
    if executable_hash(client['path'])!=client['sha256']:raise ValueError('客户端已更新，需重新确认守护基线')
    if (system or platform.system())=='Darwin':
        subprocess.run(['/usr/bin/open','-g',str(Path(client['path']).parents[2])],check=True,timeout=10,capture_output=True)
    else:
        subprocess.Popen([client['path']],cwd=str(Path(client['path']).parent),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)|getattr(subprocess,'DETACHED_PROCESS',0))


class Watchdog:
    def __init__(self,home=None,system=None,reader=None,writer=None,controller=None,clients=None,launcher=None,listener=None,tester=None,sleeper=None,authority=None):
        self.home=Path(home or Path.home());self.system=system or platform.system()
        self.reader=reader or collect;self.writer=writer or (lambda k,v:native_write(k,v,self.system))
        self.controller=controller or (lambda:discover_controller(self.home,self.system))
        self.clients=clients or (lambda:proxy_apps(self.home,self.system));self.launcher=launcher or (lambda c:launch_proxy(c,self.system))
        self.listener=listener or proxy_alive;self.tester=tester or proxy_works;self.sleep=sleeper or time.sleep
        self.authority=authority
        if authority is None and self.system=='Darwin' and platform.system()=='Darwin' and reader is None and writer is None:
            from .timezone_service import NativeTimezoneIO
            self.authority=NativeTimezoneIO().inspect

    def options(self):
        return {'clients':self.clients(),'note':'仅重开已安装并明确选择的客户端；不安装、强杀进程或回退直连。macOS 时区可在本页单独授权系统守护；用户任务不会弹出管理员授权。'}

    def validate(self,baseline):
        from .region_profiles import profiles
        if not isinstance(baseline,dict) or set(baseline)-{'timezone','locale','proxy'}:raise ValueError('守护基线无效')
        for key in ('timezone','locale'):
            if key in baseline and baseline[key] not in {p[key] for p in profiles(self.system)}:raise ValueError('守护系统基线无效')
        if 'proxy' in baseline:
            value=baseline['proxy']
            if not isinstance(value,dict) or set(value)-{'url','client','group','node','identity'} or not safe_local_proxy(value.get('url')) or not value['url'].startswith(('http://','https://')):raise ValueError('代理守护基线无效')
            if value.get('client'):
                client=value['client']
                if (not isinstance(client,dict) or not isinstance(client.get('path'),str) or not Path(client['path']).is_absolute()
                        or not isinstance(client.get('id'),str) or not isinstance(client.get('sha256'),str)
                        or not re.fullmatch('[a-f0-9]{64}',client['sha256'])):raise ValueError('批准的客户端基线无效')
            if any(k in value for k in ('group','node','identity')) and not all(isinstance(value.get(k),str) and 0<len(value[k])<=240 for k in ('group','node','identity')):raise ValueError('节点守护基线无效')

    def prepare(self,settings,options):
        allowed={'timezone','locale','proxy','client'}
        if not isinstance(options,dict) or set(options)-allowed or any(type(options.get(k,False)) is not bool for k in ('timezone','locale','proxy')):
            raise ValueError('守护选项无效')
        result={};effects=[];observed=current_region(self.reader())
        selected=profile(settings.get('region_profile'),self.system)
        for key,label in (('timezone','时区'),('locale','地区格式')):
            if not options.get(key):continue
            if not selected or settings.get(key)!=selected[key] or observed[key]!=selected[key]:
                raise ValueError('先将'+label+'配置到已选城市目标并复检，再保存守护基线')
            result[key]=selected[key];effects.append('保持'+label+'：'+selected[key]+'；漂移时读回核对并恢复，权限不足转为手动处理')
        if options.get('proxy'):
            url=settings.get('target_proxy')
            if not url:
                candidates=[p['url'] for p in discover_proxies(self.home,self.system) if p['url'].startswith(('http://','https://'))]
                url=candidates[0] if len(candidates)==1 else None
            if not url or not safe_local_proxy(url) or not url.startswith(('http://','https://')) or not self.tester(url):
                raise ValueError('代理守护需要唯一且已通过 API TLS 测试的本机 HTTP 端口；请先填写、验证并保存目标代理')
            proxy={'url':url}
            client=next((c for c in self.clients() if c['id']==options.get('client')),None)
            if options.get('client') and not client:raise ValueError('所选客户端已变化，请重新读取')
            if client:proxy['client']={**client,'sha256':executable_hash(client['path'])}
            try:
                controller=self.controller();groups=controller.groups()
                if len(groups)==1 and groups[0].get('now') in groups[0]['nodes']:
                    proxy.update(group=groups[0]['name'],node=groups[0]['now'],identity=controller.identity)
            except (OSError,ValueError):pass
            if not client and not proxy.get('group'):
                raise ValueError('未找到可重开的客户端或唯一可恢复的节点组，不能承诺自动修复；请手动处理')
            result['proxy']=proxy
            effects.append('守护代理 '+url+'：离线时'+('重开 '+client['label'] if client else '记录手动处理')+'，不强杀运行进程、不改端口、不回退直连')
            if proxy.get('node'):effects.append('恢复代理组 '+proxy['group']+' 的批准节点 '+proxy['node']+'；影响该组新连接，复检失败将尝试恢复修改前节点')
        return result,effects

    def unchanged(self,baseline):
        current=current_region(self.reader())
        if any(current.get(k)!=baseline[k] for k in ('timezone','locale') if k in baseline):return False
        proxy=baseline.get('proxy')
        if proxy:
            if not self.tester(proxy['url']):return False
            if proxy.get('client') and executable_hash(proxy['client']['path'])!=proxy['client']['sha256']:return False
            if proxy.get('group'):
                c=self.controller();row=next((g for g in c.groups() if g['name']==proxy['group']),{})
                if c.identity!=proxy['identity'] or row.get('now')!=proxy['node']:return False
        return True

    def run(self,baseline,stats,event,persist):
        now=datetime.now(timezone.utc).timestamp();records=stats.setdefault('watchdog',{});changed=False
        for key,target in baseline.items():
            record=records.setdefault(key,{'attempts':[]})
            label={'timezone':'时区','locale':'地区格式','proxy':'代理'}[key]
            def mark(state,note):
                if record.get('state')!=state or record.get('note')!=note:event('watchdog_'+state,note,component=key)
                record.update(state=state,note=note)
            try:
                if record.get('pending'):
                    mark('attention','上轮守护写入未完整结束，请核对日志并重新批准基线');continue
                observed=current_region(self.reader()) if key!='proxy' else {}
                controller=None;row=None
                if key=='proxy':
                    online=self.listener(target['url']);good=online and self.tester(target['url'])
                    if good and target.get('group'):
                        controller=self.controller();row=next((g for g in controller.groups() if g['name']==target['group']),None)
                        if controller.identity!=target['identity'] or not row:raise ValueError('节点控制配置变化，需重新批准基线')
                    drift=not good or row is not None and row['now']!=target['node']
                else:drift=observed.get(key)!=target
                if not drift:mark('healthy','批准的'+label+'基线正常');continue
                if key=='timezone' and self.system=='Darwin' and self.authority:
                    try:authority=self.authority()
                    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
                        mark('attention','系统时区服务状态无法核实，未并发写入；请在持续维护页核对。');continue
                    if authority.get('pending') or authority.get('legacy_registered'):
                        mark('attention','系统时区服务有未完成操作或旧任务冲突，请先在持续维护页处理。');continue
                    if authority.get('baseline') and (not authority.get('registered') or authority['baseline'].get('target')!=target):
                        mark('attention','系统时区守护与用户任务的基线不一致或尚未注册；未覆盖，请重新批准本次维护方案。');continue
                    if authority.get('registered'):
                        heartbeat=authority.get('status',{});stamp=heartbeat.get('at_epoch')
                        healthy=(type(stamp) in (int,float) and 0<=now-stamp<180
                                 and heartbeat.get('state') in ('healthy','restored','repairing','cooldown') and heartbeat.get('initial') is False)
                        mark('delegated' if healthy else 'attention','时区漂移已交给获授权的系统守护，等待下次 60 秒检查并读回。' if healthy else '已注册系统时区守护，但心跳过期或恢复已暂停；请在本页核对状态并重新批准。')
                        continue
                attempts=record.get('attempts',[])
                if any(not isinstance(t,(int,float)) or t>now for t in attempts):raise ValueError('守护时间记录异常，请核对系统时钟')
                attempts=[t for t in attempts if now-t<86400]
                if len(attempts)>=3:mark('paused','24 小时已尝试恢复 3 次，暂停'+label+'自动恢复；请检查冲突设置并重新批准');continue
                if attempts and now-attempts[-1]<300:mark('cooldown','恢复冷却中，至少间隔 5 分钟；'+label+'仍需复检');continue
                before=observed.get(key) if key!='proxy' else row.get('now') if row else 'offline' if not online else 'API TLS unavailable'
                event('watchdog_drift','发现'+label+'漂移，准备恢复批准基线',component=key,before=before,target=target if key!='proxy' else target.get('node') or target['url'])
                record.update(attempts=attempts+[now],pending=True);persist()
                try:
                    if key!='proxy':
                        if not before:raise ValueError('未取得当前系统值，不覆盖未知状态')
                        changed=True  # Even a failed command may have partially changed state.
                        self.writer(key,target)
                        if current_region(self.reader()).get(key)!=target:raise ValueError('写入后读回不一致')
                    elif not online:
                        if not target.get('client'):raise ValueError('代理已离线，未批准可重开的客户端')
                        client=target['client']
                        if not any(c['id']==client['id'] and c['path']==client['path'] for c in self.clients()) or executable_hash(client['path'])!=client['sha256']:
                            raise ValueError('客户端路径或版本已变化，请重新批准守护基线')
                        changed=True
                        self.launcher(target['client'])
                        for _ in range(5):
                            if self.listener(target['url']):break
                            self.sleep(1)
                        if not self.listener(target['url']) or not self.tester(target['url']):raise ValueError('客户端已请求启动，但代理 API TLS 尚未恢复')
                        if target.get('group'):
                            restored=self.controller();current=next((g for g in restored.groups() if g['name']==target['group']),None)
                            if restored.identity!=target['identity'] or not current:raise ValueError('代理重开后控制接口或节点组变化，需手动核对')
                            if current['now']!=target['node']:
                                previous=current['now'];restored.select(target['group'],target['node'],previous)
                                if not self.tester(target['url']):
                                    restored.select(target['group'],previous,target['node'],restore=True)
                                    raise ValueError('重开后的基线节点未通过复检，已恢复原节点')
                    elif row and row['now']!=target['node']:
                        previous=row['now'];changed=True;controller.select(target['group'],target['node'],previous)
                        if not self.tester(target['url']):
                            controller.select(target['group'],previous,target['node'],restore=True)
                            raise ValueError('基线节点复检失败，已恢复切换前节点')
                    else:raise ValueError('本机代理在运行但上游不可用，未反复重启；请核对节点或服务状态')
                    changed=True;mark('restored','已恢复'+label+'批准基线并读回复检；不代表账号或全部流量可用')
                except (OSError,ValueError,subprocess.SubprocessError) as error:
                    mark('attention','未确认'+label+'恢复：'+str(error)[:180])
                finally:record['pending']=False;persist()
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                mark('attention',label+'守护需要处理：'+str(error)[:180])
        return changed
