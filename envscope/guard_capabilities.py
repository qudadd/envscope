"""Read current-token privileges; never enable rights or modify policy here."""
import platform


def write_capabilities(system=None):
    system = system or platform.system()
    timezone = {'state': 'authorization_required', 'source': 'system-service',
                'reason': '系统时区保持需要单独授权受保护的后台任务。'}
    if system == 'Windows' and platform.system() == 'Windows':
        try:
            import ctypes
            from ctypes import wintypes
            class LUID(ctypes.Structure):
                _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]
            class Entry(ctypes.Structure):
                _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]
            advapi = ctypes.WinDLL('advapi32', use_last_error=True)
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            advapi.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
            advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
            token = wintypes.HANDLE(); luid = LUID(); size = wintypes.DWORD()
            if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
                raise OSError('token unavailable')
            try:
                if not advapi.LookupPrivilegeValueW(None, 'SeTimeZonePrivilege', ctypes.byref(luid)):
                    raise OSError('privilege unavailable')
                advapi.GetTokenInformation(token, 3, None, 0, ctypes.byref(size))
                if not 4 <= size.value <= 65536:
                    raise OSError('invalid token size')
                data = ctypes.create_string_buffer(size.value)
                if not advapi.GetTokenInformation(token, 3, data, size, ctypes.byref(size)):
                    raise OSError('token unavailable')
                count = wintypes.DWORD.from_buffer(data).value
                if 4 + count * ctypes.sizeof(Entry) > size.value:
                    raise OSError('invalid token')
                entries = (Entry * count).from_buffer(data, 4)
                present = any(row.Luid.LowPart == luid.LowPart and row.Luid.HighPart == luid.HighPart and not row.Attributes & 4 for row in entries)
                timezone = {'state': 'available' if present else 'authorization_required', 'source': 'user-token',
                            'reason': '当前用户令牌具备更改时区权限；每次后台运行仍会复核。' if present else '当前用户没有更改时区权限，启用保持前需要授权系统时区任务。'}
            finally:
                kernel.CloseHandle(token)
        except (OSError, ValueError, ImportError):
            timezone = {'state': 'unavailable', 'source': 'user-token', 'reason': '未能核实后台时区权限，不能声明可自动恢复。'}
    return {'timezone': timezone, 'locale': {'state': 'available', 'source': 'user-session',
             'reason': '仅在原用户会话中恢复地区格式。'}}
