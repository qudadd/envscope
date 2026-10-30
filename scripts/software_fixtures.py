"""Create only disposable Shell Links for Unicode interoperability tests."""
import ctypes
from pathlib import Path
import tempfile
from envscope.windows_shortcut import _Shortcut


def shortcut(path,target,args):
    path=Path(path).resolve();temporary=Path(tempfile.gettempdir()).resolve()
    if not path.is_relative_to(temporary) or path.exists() or path.suffix!='.lnk':
        raise ValueError('Shell Link fixture requires a new path within OS temp')
    with _Shortcut() as link:
        link.check(link.call(link.link,20,[ctypes.c_wchar_p],str(target)))
        link.check(link.call(link.link,11,[ctypes.c_wchar_p],args))
        link.check(link.call(link.file,6,[ctypes.c_wchar_p,ctypes.c_int],str(path),1))
