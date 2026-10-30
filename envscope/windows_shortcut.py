"""Read Shell Link Unicode metadata without Resolve, execution, or WSH encoding."""
import ctypes
import os
from pathlib import Path
import uuid
from .component_inventory import read_regular


class _Shortcut:
    def __init__(self):
        if os.name!='nt':raise OSError('Shell Link metadata is Windows-only')
        from ctypes import wintypes
        self.H=ctypes.c_long;self.P=ctypes.c_void_p
        self.api=ctypes.OleDLL('ole32');self.api.CoInitializeEx.argtypes=[self.P,wintypes.DWORD];self.api.CoInitializeEx.restype=self.H
        self.api.CoUninitialize.argtypes=[];self.api.CoUninitialize.restype=None
        self.api.CoCreateInstance.argtypes=[self.P,self.P,wintypes.DWORD,self.P,ctypes.POINTER(self.P)];self.api.CoCreateInstance.restype=self.H
        result=self.api.CoInitializeEx(None,2)
        self.uninitialize=result in (0,1);self.link=self.P();self.file=self.P()
        if result<0 and result!=-2147417850:self.check(result)
        try:
            clsid=self.guid('00021401-0000-0000-c000-000000000046');iid=self.guid('000214f9-0000-0000-c000-000000000046')
            self.check(self.api.CoCreateInstance(clsid,None,1,iid,ctypes.byref(self.link)))
            persist=self.guid('0000010b-0000-0000-c000-000000000046')
            self.check(self.call(self.link,0,[self.P,ctypes.POINTER(self.P)],persist,ctypes.byref(self.file)))
        except BaseException:self.close();raise

    @staticmethod
    def guid(value):return ctypes.create_string_buffer(uuid.UUID(value).bytes_le,16)
    @staticmethod
    def check(result):
        if result<0:raise OSError(result,'Windows Shell Link metadata operation failed')
    def call(self,pointer,index,types,*args):
        table=ctypes.cast(pointer,ctypes.POINTER(ctypes.POINTER(self.P))).contents
        function=ctypes.WINFUNCTYPE(self.H,self.P,*types)(table[index])
        return function(pointer,*args)
    def close(self):
        for pointer in (self.file,self.link):
            if pointer:self.call(pointer,2,[])
        self.file=self.P();self.link=self.P()
        if self.uninitialize:self.api.CoUninitialize();self.uninitialize=False
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def read_shortcut(path):
    path=Path(path)
    if read_regular(path,limit=1024*1024) is None:raise ValueError('Shortcut is absent')
    with _Shortcut() as link:
        link.check(link.call(link.file,5,[ctypes.c_wchar_p,ctypes.c_uint32],str(path),0))
        target=ctypes.create_unicode_buffer(32768);args=ctypes.create_unicode_buffer(8192)
        link.check(link.call(link.link,3,[ctypes.c_wchar_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32],target,len(target),None,4))
        link.check(link.call(link.link,10,[ctypes.c_wchar_p,ctypes.c_int],args,len(args)))
        if len(target.value)>=len(target)-1 or len(args.value)>=len(args)-1:raise ValueError('Shortcut metadata is truncated')
        return {'target':target.value,'args':args.value}
