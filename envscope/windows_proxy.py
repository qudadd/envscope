"""Read LAN automatic-proxy flags through WinINet; never fetch or execute PAC.

https://learn.microsoft.com/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw
"""
import ctypes


def automatic_proxy_flags(query=None):
    # Explicit 32-bit DWORD also makes structure-layout fixture tests portable.
    DWORD = ctypes.c_uint32
    class FILETIME(ctypes.Structure):
        _fields_ = [('low', DWORD), ('high', DWORD)]
    class Value(ctypes.Union):
        _fields_ = [('number', DWORD), ('text', ctypes.c_void_p), ('time', FILETIME)]
    class Option(ctypes.Structure):
        _fields_ = [('option', DWORD), ('value', Value)]
    class Options(ctypes.Structure):
        _fields_ = [('size', DWORD), ('connection', ctypes.c_void_p), ('count', DWORD),
                    ('error', DWORD), ('options', ctypes.POINTER(Option))]
    if query is None:
        query = ctypes.WinDLL('wininet', use_last_error=True).InternetQueryOptionW
        query.argtypes = [ctypes.c_void_p, DWORD, ctypes.c_void_p, ctypes.POINTER(DWORD)]
        query.restype = ctypes.c_int
    # FLAGS_UI (10) is the documented Windows 7+ query; FLAGS (1) is fallback.
    for key in (10, 1):
        option = Option()
        option.option = key
        options = Options(ctypes.sizeof(Options), None, 1, 0, ctypes.pointer(option))
        size = DWORD(ctypes.sizeof(options))
        if query(None, 75, ctypes.byref(options), ctypes.byref(size)):
            flags = option.value.number
            return {'auto_detect': bool(flags & 8), 'pac_configured': bool(flags & 4),
                    'source': 'wininet-lan-flags'}
    return {'auto_detect': None, 'pac_configured': None, 'source': 'unavailable'}
