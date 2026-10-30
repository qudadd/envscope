"""Notify once for actionable transitions, excluding logs and private values."""
import hashlib
import json
import time

LABELS={'timezone':'时区','locale':'地区格式','proxy':'代理','code':'Code 配置','scheduler':'后台巡检'}


class GuardNotifications:
    def __init__(self,store,sink,clock=time.time):
        self.store,self.sink=store,sink
        self.clock=clock
        self.saved=store._read('guard-notifications.private.json',{})
        if not isinstance(self.saved,dict):self.saved={}
        self.active=False

    def update(self,maintenance,timezone):
        saved=self.saved
        expected=saved.get('timezone_expected',False)
        if timezone.get('installed') is True:expected=True
        elif timezone.get('intentionally_removed') is True:expected=False
        waiting=saved.get('waiting_since')
        if expected and timezone.get('state')=='waiting':
            if not isinstance(waiting,(int,float)) or waiting>self.clock():waiting=self.clock()
        else:waiting=None
        issues={}
        if maintenance.get('enabled') is True:
            for name,row in maintenance.get('watchdog',{}).items():
                if name in LABELS and row.get('state') in ('attention','paused'):
                    issues[name]=row['state']
            if maintenance.get('state') in ('failed','stale','schedule_unverified'):issues['scheduler']=maintenance['state']
            if maintenance.get('restore_state') in ('blocked','unverified','paused'):issues['code']=maintenance['restore_state']
        if expected and timezone.get('state') in ('attention','conflict','recovery_required','unregistered','outdated'):
            issues['timezone']=timezone['state']
        if expected and timezone.get('state')=='not_installed':issues['timezone']='unexpected_removal'
        if waiting is not None and self.clock()-waiting>=180:issues['timezone']='heartbeat_lost'
        fingerprint=hashlib.sha256(json.dumps(issues,sort_keys=True).encode()).hexdigest() if issues else ''
        changed=bool(issues and fingerprint!=saved.get('fingerprint'))
        if changed:
            names=sorted(issues)
            self.sink({'components':names,'message':'、'.join(LABELS[name] for name in names)+'需要处理。打开守护方案查看原因与恢复入口。'})
        self.active=bool(issues)
        self.saved={'fingerprint':fingerprint,'timezone_expected':expected,'waiting_since':waiting}
        if self.saved!=saved:self.store._write('guard-notifications.private.json',self.saved)
        return changed
