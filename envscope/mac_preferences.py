"""Typed AppleLanguages access for one fixed application and the current user."""
from contextlib import contextmanager
import ctypes as C
import os
import platform
import plistlib
import re

DOMAIN='com.anthropic.claudefordesktop'
KEY='AppleLanguages'
HOSTS=('any','current')


def language_array(value):
    if (not isinstance(value,list) or len(value)>32 or any(not isinstance(v,str) or len(v)>255
        or not re.fullmatch(r'[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*',v) for v in value)):
        raise ValueError('应用语言不是可核对的语言代码列表，保留原值，请在系统的应用语言设置中处理')
    return value


def validate_model(value):
    if not isinstance(value,dict) or set(value)!={'present','value'} or type(value['present']) is not bool:
        raise ValueError('应用语言原值记录无法核对')
    if value['present']:language_array(value['value'])
    elif value['value'] is not None:raise ValueError('应用语言缺省记录无法核对')
    return value


def validate_snapshot(value):
    if not isinstance(value,dict) or set(value)!={*HOSTS,'effective','forced'} or type(value['forced']) is not bool:
        raise ValueError('应用语言快照无法核对')
    for key in (*HOSTS,'effective'):validate_model(value[key])
    return value


class ClaudePreferences:
    """No arbitrary domain, global write, root user or preference key input.

    CI may select its own unique disposable domain. That gate is unavailable to
    product API requests and never redirects a write to a real test application.
    """
    def __init__(self,*,fixture_domain=None):
        if platform.system()!='Darwin':raise ValueError('应用专用语言写入仅支持 macOS')
        self.domain=DOMAIN
        if fixture_domain is not None:
            if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('ENVSCOPE_CLIENT_ACCEPTANCE')!='1'
                or not isinstance(fixture_domain,str) or not re.fullmatch(r'io\.qudadd\.envscope\.fixture\.[a-f0-9]{32}',fixture_domain)):
                raise ValueError('仅隔离 CI 可使用一次性偏好域')
            self.domain=fixture_domain
        self.cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        P=C.c_void_p;I=C.c_long;B=C.c_ubyte
        signatures={
            'CFStringCreateWithCString':([P,C.c_char_p,C.c_uint32],P),'CFRelease':([P],None),
            'CFPreferencesCopyValue':([P,P,P,P],P),'CFPreferencesCopyAppValue':([P,P],P),
            'CFPreferencesSetValue':([P,P,P,P,P],None),'CFPreferencesSynchronize':([P,P,P],B),
            'CFPreferencesAppValueIsForced':([P,P],B),'CFPropertyListCreateData':([P,P,I,C.c_ulong,C.POINTER(P)],P),
            'CFDataGetLength':([P],I),'CFDataGetBytePtr':([P],C.POINTER(B)),
            'CFDataCreate':([P,C.c_char_p,I],P),'CFPropertyListCreateWithData':([P,P,C.c_ulong,C.POINTER(I),C.POINTER(P)],P)}
        for name,(arguments,result) in signatures.items():
            function=getattr(self.cf,name);function.argtypes=arguments;function.restype=result
        self.user=P.in_dll(self.cf,'kCFPreferencesCurrentUser').value
        self.hosts={k:P.in_dll(self.cf,'kCFPreferences'+('AnyHost' if k=='any' else 'CurrentHost')).value for k in HOSTS}
        self.global_domain=P.in_dll(self.cf,'kCFPreferencesAnyApplication').value

    @contextmanager
    def _strings(self,*values):
        pointers=[]
        try:
            for value in values:
                pointer=self.cf.CFStringCreateWithCString(None,value.encode('utf-8'),0x08000100)
                if not pointer:raise ValueError('系统无法创建偏好标识')
                pointers.append(pointer)
            yield pointers
        finally:
            for pointer in reversed(pointers):self.cf.CFRelease(pointer)

    def _decode(self,pointer):
        if not pointer:return {'present':False,'value':None}
        error=C.c_void_p();data=None
        try:
            data=self.cf.CFPropertyListCreateData(None,pointer,200,0,C.byref(error))
            if not data:raise ValueError('系统偏好类型无法读取')
            length=self.cf.CFDataGetLength(data)
            if not 0<length<=65536:raise ValueError('系统偏好长度无法核对')
            return {'present':True,'value':plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data),length))}
        finally:
            if data:self.cf.CFRelease(data)
            if error.value:self.cf.CFRelease(error.value)
            self.cf.CFRelease(pointer)

    def _sync(self,app,host):
        if not self.cf.CFPreferencesSynchronize(app,self.user,self.hosts[host]):
            raise ValueError('系统未确认当前用户的应用偏好同步，未判定修改成功')

    def _read_host(self,key,app,host):
        self._sync(app,host)
        return self._decode(self.cf.CFPreferencesCopyValue(key,app,self.user,self.hosts[host]))

    def read(self):
        with self._strings(KEY,self.domain) as (key,app):
            value={host:validate_model(self._read_host(key,app,host)) for host in HOSTS}
            value['forced']=bool(self.cf.CFPreferencesAppValueIsForced(key,app))
            value['effective']=validate_model(self._decode(self.cf.CFPreferencesCopyAppValue(key,app)))
            return validate_snapshot(value)

    def set_host(self,host,model,expected):
        if host not in HOSTS:raise ValueError('应用语言范围无效')
        validate_model(model);validate_model(expected)
        with self._strings(KEY,self.domain) as (key,app):
            if self.cf.CFPreferencesAppValueIsForced(key,app):raise ValueError('应用语言由管理策略强制设置，未覆盖')
            if self._read_host(key,app,host)!=expected:raise ValueError('应用语言在预览后改变，没有覆盖后续修改')
            pointer=data=None;error=C.c_void_p()
            try:
                if model['present']:
                    raw=plistlib.dumps(model['value'],fmt=plistlib.FMT_BINARY)
                    data=self.cf.CFDataCreate(None,raw,len(raw))
                    if not data:raise ValueError('系统无法准备应用语言列表')
                    pointer=self.cf.CFPropertyListCreateWithData(None,data,0,None,C.byref(error))
                    if not pointer:raise ValueError('系统无法解析应用语言列表')
                self.cf.CFPreferencesSetValue(key,pointer,app,self.user,self.hosts[host])
                self._sync(app,host)
                if self._read_host(key,app,host)!=model:raise ValueError('应用语言写入后未能独立读回')
            finally:
                if pointer:self.cf.CFRelease(pointer)
                if data:self.cf.CFRelease(data)
                if error.value:self.cf.CFRelease(error.value)

    def reference(self):
        """Read-only CI witness; no values from this snapshot are published."""
        value={}
        for domain,app in (('claude',DOMAIN),('global',None)):
            with self._strings(KEY,app or DOMAIN,'AppleLocale') as (key,identifier,locale):
                identifier=identifier if app else self.global_domain
                value[domain]={host:{'language':self._read_host(key,identifier,host),
                                     'locale':self._read_host(locale,identifier,host)} for host in HOSTS}
        return value


def read_claude_language():
    value=ClaudePreferences().read();effective=value['effective']['value']
    explicit=any(value[k]['present'] for k in HOSTS) or value['forced']
    return {'value':effective[0] if effective else None,'source':'application-preference' if explicit else 'application-fallback',
            'managed':value['forced'],'scope':'current-user-application-preference-not-rendered-ui'}
