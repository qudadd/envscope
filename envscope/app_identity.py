"""Stable open-source package identity; metadata is not a publisher signature."""
import json
from pathlib import Path
import re

from . import __release__, __version__

APP_ID='io.qudadd.envscope'


def build_identity(system):
    if system not in ('Windows','Darwin'):raise ValueError('Unsupported desktop platform')
    return {'format':1,'app_id':APP_ID,'version':__version__,'release':__release__,
            'build_version':__version__,'system':system,
            'signature_mode':'ad-hoc' if system=='Darwin' else 'unsigned',
            'publisher_verified':False,'notarized':False}


def validate_identity(value,system,release):
    expected='ad-hoc' if system=='Darwin' else 'unsigned'
    if (not isinstance(value,dict) or type(value.get('format')) is not int or value['format']!=1
            or value.get('app_id')!=APP_ID or value.get('release')!=release or value.get('system')!=system
            or not re.fullmatch(r'v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?',release)
            or value.get('version')!=release[1:].split('-')[0] or value.get('build_version')!=value.get('version')
            or value.get('signature_mode')!=expected or value.get('publisher_verified') is not False
            or value.get('notarized') is not False):
        raise ValueError('更新包应用身份、版本或开源构建标识不符合当前发布规则，已停止安装。')
    return value


def identity_path(executable,system):
    executable=Path(executable)
    return (executable.parent.parent/'Resources' if system=='Darwin' else executable.parent)/'build-identity.json'


def verify_package_identity(executable,system,release):
    path=identity_path(executable,system)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>16384:
        raise ValueError('更新包缺少有效的应用身份记录，已停止安装。')
    try:value=json.loads(path.read_text(encoding='utf-8'))
    except (ValueError,UnicodeError):raise ValueError('应用身份记录无效。') from None
    return validate_identity(value,system,release)
