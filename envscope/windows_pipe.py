"""Bounded local HTTP over a verified Windows core named pipe.

No remote pipe, HTTP proxy, redirects or authentication fallback. Identification
QoS prevents the server from impersonating this client. All I/O has one deadline.
"""
import ctypes
from ctypes import wintypes
import io
import os
from pathlib import PureWindowsPath
import re
import time


CORES={'mihomo.exe','verge-mihomo.exe','clash-meta.exe','clash.exe','clash-rs.exe'}
SERVICE_SIDS={'S-1-5-18','S-1-5-19','S-1-5-20'}


def validate_pipe(value):
    if not isinstance(value,str) or not re.fullmatch(r'\\\\\.\\pipe\\[A-Za-z0-9_.{}() -]{1,200}',value,re.I):
        raise ValueError('仅支持已配置的 Windows 本机命名管道，不连接远程或设备路径')
    return value


def validate_peer(image,sid,current_sid):
    if (not isinstance(image,str) or not PureWindowsPath(image).is_absolute() or PureWindowsPath(image).name.casefold() not in CORES
            or not isinstance(sid,str) or not isinstance(current_sid,str) or not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+',current_sid)
            or sid not in SERVICE_SIDS|{current_sid}):
        raise ValueError('本机管道服务端不是可识别的当前用户或系统代理内核，未发送认证信息')


class Overlapped(ctypes.Structure):
    _fields_=[('Internal',ctypes.c_size_t),('InternalHigh',ctypes.c_size_t),
              ('Offset',wintypes.DWORD),('OffsetHigh',wintypes.DWORD),('hEvent',wintypes.HANDLE)]


class _Reader(io.RawIOBase):
    def __init__(self,owner):super().__init__();self.owner=owner
    def readable(self):return True
    def readinto(self,buffer):
        data=self.owner.read(len(buffer));buffer[:len(data)]=data;return len(data)


class NamedPipeSocket:
    def __init__(self,path,timeout=5):
        self.path=validate_pipe(path);self.handle=None
        if os.name!='nt':raise ValueError('本机命名管道需要 Windows')
        if type(timeout) not in (int,float) or not 0<timeout<=15:raise ValueError('管道期限无效')
        self.deadline=time.monotonic()+timeout
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.security=ctypes.WinDLL('advapi32',use_last_error=True)
        self._prototypes()
        try:
            self._connect();self._verify_peer()
        except BaseException:
            self.close();raise

    def _prototypes(self):
        k=self.kernel;a=self.security
        def signature(lib,name,args,result):
            function=getattr(lib,name);function.argtypes=args;function.restype=result
        handle=wintypes.HANDLE;dword=wintypes.DWORD;boolean=wintypes.BOOL;ptr=ctypes.c_void_p
        signature(k,'CreateFileW',[wintypes.LPCWSTR,dword,dword,ptr,dword,dword,handle],handle)
        signature(k,'WaitNamedPipeW',[wintypes.LPCWSTR,dword],boolean)
        signature(k,'CreateEventW',[ptr,boolean,boolean,wintypes.LPCWSTR],handle)
        signature(k,'ReadFile',[handle,ptr,dword,ctypes.POINTER(dword),ctypes.POINTER(Overlapped)],boolean)
        signature(k,'WriteFile',[handle,ptr,dword,ctypes.POINTER(dword),ctypes.POINTER(Overlapped)],boolean)
        signature(k,'GetOverlappedResult',[handle,ctypes.POINTER(Overlapped),ctypes.POINTER(dword),boolean],boolean)
        signature(k,'WaitForSingleObject',[handle,dword],dword)
        signature(k,'CancelIoEx',[handle,ctypes.POINTER(Overlapped)],boolean)
        signature(k,'CloseHandle',[handle],boolean)
        signature(k,'GetNamedPipeServerProcessId',[handle,ctypes.POINTER(dword)],boolean)
        signature(k,'OpenProcess',[dword,boolean,dword],handle)
        signature(k,'GetCurrentProcess',[],handle)
        signature(k,'QueryFullProcessImageNameW',[handle,dword,wintypes.LPWSTR,ctypes.POINTER(dword)],boolean)
        signature(a,'OpenProcessToken',[handle,dword,ctypes.POINTER(handle)],boolean)
        signature(a,'GetTokenInformation',[handle,ctypes.c_int,ptr,dword,ctypes.POINTER(dword)],boolean)
        signature(a,'ConvertSidToStringSidW',[ptr,ctypes.POINTER(wintypes.LPWSTR)],boolean)
        signature(k,'LocalFree',[ptr],ptr)

    def _remaining(self):
        value=int((self.deadline-time.monotonic())*1000)
        if value<=0:raise TimeoutError('本机管道响应超时')
        return value

    def _connect(self):
        # OVERLAPPED | SQOS_PRESENT | IDENTIFICATION. Never grant impersonation.
        flags=0x40000000|0x00100000|0x00010000
        invalid=ctypes.c_void_p(-1).value
        while True:
            self._remaining()
            value=self.kernel.CreateFileW(self.path,0xC0000000,0,None,3,flags,None)
            if value not in (None,invalid):self.handle=value;return
            if ctypes.get_last_error()!=231:raise OSError('本机代理管道尚未就绪或没有连接权限')
            if not self.kernel.WaitNamedPipeW(self.path,self._remaining()):
                raise TimeoutError('等待本机代理管道超时')

    def _sid(self,process):
        token=wintypes.HANDLE()
        if not self.security.OpenProcessToken(process,8,ctypes.byref(token)):
            raise ValueError('无法读取本机管道服务端身份')
        try:
            size=wintypes.DWORD()
            self.security.GetTokenInformation(token,1,None,0,ctypes.byref(size))
            if not 0<size.value<65536:raise ValueError('管道服务端身份格式异常')
            data=ctypes.create_string_buffer(size.value)
            if not self.security.GetTokenInformation(token,1,data,len(data),ctypes.byref(size)):
                raise ValueError('无法核对管道服务端身份')
            sid=ctypes.cast(data,ctypes.POINTER(ctypes.c_void_p))[0];text=wintypes.LPWSTR()
            if not self.security.ConvertSidToStringSidW(sid,ctypes.byref(text)):
                raise ValueError('管道服务端身份无法转换')
            try:return text.value
            finally:self.kernel.LocalFree(ctypes.cast(text,ctypes.c_void_p))
        finally:self.kernel.CloseHandle(token)

    def _verify_peer(self):
        pid=wintypes.DWORD()
        if not self.kernel.GetNamedPipeServerProcessId(self.handle,ctypes.byref(pid)) or not pid.value:
            raise ValueError('未取得本机管道的服务端进程')
        process=self.kernel.OpenProcess(0x1000,False,pid.value)
        if not process:raise ValueError('管道服务端进程归属无法读取')
        try:
            size=wintypes.DWORD(32768);image=ctypes.create_unicode_buffer(size.value)
            if not self.kernel.QueryFullProcessImageNameW(process,0,image,ctypes.byref(size)):
                raise ValueError('管道服务端程序路径无法读取')
            validate_peer(image.value,self._sid(process),self._sid(self.kernel.GetCurrentProcess()))
        finally:self.kernel.CloseHandle(process)
        self._remaining()

    def _io(self,data,writing):
        if self.handle is None:raise OSError('本机管道已关闭')
        self._remaining();event=self.kernel.CreateEventW(None,True,False,None)
        if not event:raise OSError('无法创建本机管道等待事件')
        operation=Overlapped();operation.hEvent=event;count=wintypes.DWORD()
        buffer=ctypes.create_string_buffer(data)
        size=len(data) if writing else data
        try:
            function=self.kernel.WriteFile if writing else self.kernel.ReadFile
            ok=function(self.handle,buffer,size,ctypes.byref(count),ctypes.byref(operation))
            error=0 if ok else ctypes.get_last_error()
            if not ok and error==997:
                try:wait=self.kernel.WaitForSingleObject(event,self._remaining())
                except TimeoutError:wait=258
                if wait!=0:
                    # Named pipe overlapped operations support cancellation. Wait
                    # for completion before releasing buffers referenced by the OS.
                    self.kernel.CancelIoEx(self.handle,ctypes.byref(operation))
                    self.kernel.GetOverlappedResult(self.handle,ctypes.byref(operation),ctypes.byref(count),True)
                    raise TimeoutError('本机代理管道响应超时')
                ok=self.kernel.GetOverlappedResult(self.handle,ctypes.byref(operation),ctypes.byref(count),False)
                error=0 if ok else ctypes.get_last_error()
            if not ok and error not in (234,109,232):raise OSError('本机代理管道读写失败')
            if writing:
                if not ok or not count.value:raise OSError('本机代理管道写入未完成')
                return count.value
            return buffer.raw[:count.value] if ok or error==234 else b''
        finally:self.kernel.CloseHandle(event)

    def sendall(self,data):
        offset=0
        while offset<len(data):offset+=self._io(data[offset:],True)

    def read(self,size):return self._io(min(size,65536),False)
    def makefile(self,mode='rb',*args,**kwargs):
        if mode!='rb':raise ValueError('本机管道只提供 HTTP 二进制读取')
        return io.BufferedReader(_Reader(self))
    def close(self):
        if self.handle is not None:
            self.kernel.CancelIoEx(self.handle,None);self.kernel.CloseHandle(self.handle);self.handle=None
