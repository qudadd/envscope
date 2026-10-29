"""Independent file copies. APFS clones share blocks, never writable identities."""
import ctypes
import errno
import os
import shutil
import sys


def _clone(source, destination):
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    clone = libc.clonefile
    clone.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    clone.restype = ctypes.c_int
    # CLONE_NOFOLLOW: do not follow a source link introduced during a race.
    if clone(os.fsencode(source), os.fsencode(destination), 1) != 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


def copy_profile_file(source, destination):
    if sys.platform == 'darwin':
        try:
            _clone(source, destination)
        except OSError as error:
            # No cleanup of a failed clone: an unexpected destination is evidence.
            if (error.errno not in {errno.EXDEV, errno.ENOTSUP, errno.EINVAL, errno.ENOSYS}
                    or os.path.lexists(destination)):
                raise
        else:
            shutil.copystat(source, destination, follow_symlinks=False)
            return str(destination)
    return shutil.copy2(source, destination, follow_symlinks=False)
