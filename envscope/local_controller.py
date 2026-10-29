"""Configured local core access, including macOS Unix sockets; never scan ports."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import socket
import stat
from urllib.request import Request, ProxyHandler, build_opener

from .controller import NoRedirects, validate_controller
from .discovery import config_directories
from .remedies import _read, _safe
from .routing_config import load_yaml


class LocalController:
    def __init__(self, origin=None, secret='', unix=None):
        if bool(origin) == bool(unix):
            raise ValueError('控制接口必须唯一')
        if not isinstance(secret, str) or len(secret) > 4096 or any(ord(c) < 32 or ord(c) > 126 for c in secret):
            raise ValueError('控制接口认证格式无法识别')
        self.origin = validate_controller(origin) if origin else None
        self.unix = str(unix) if unix else None
        self.headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        if secret:
            self.headers['Authorization'] = 'Bearer ' + secret
        self.identity = hashlib.sha256(((self.origin or self.unix) + '\0' + secret).encode()).hexdigest()

    def request(self, path, data=None):
        if path not in ('/configs', '/rules', '/proxies', '/configs?force=true'):
            raise ValueError('控制接口操作不在允许范围')
        if data is not None and path != '/configs?force=true':
            raise ValueError('此接口仅允许读取')
        body = None if data is None else json.dumps(data).encode()
        connection = None
        try:
            if self.unix:
                # Recheck socket ownership before every connection. Unix sockets
                # are local, but a replaced path must not receive credentials.
                validate_socket(self.unix)
                connection = http.client.HTTPConnection('localhost', timeout=5)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.settimeout(5)
                    sock.connect(self.unix)
                except BaseException:
                    sock.close()
                    raise
                connection.sock = sock
                connection.request('GET' if body is None else 'PUT', path, body, self.headers)
                response = connection.getresponse()
            else:
                opener = build_opener(ProxyHandler({}), NoRedirects())
                response = opener.open(Request(self.origin + path, body, self.headers,
                                               method='GET' if body is None else 'PUT'), timeout=5)
            with response:
                raw = response.read(1048577)
                if response.status not in (200, 204) or len(raw) > 1048576:
                    raise ValueError('invalid response')
            value = json.loads(raw) if raw else {}
            if not isinstance(value, dict):
                raise ValueError('invalid response type')
            return value
        except (OSError, ValueError, http.client.HTTPException) as error:
            raise ValueError('本机控制接口未授权、不可达或响应无效；请在代理客户端核对') from error
        finally:
            if connection:
                connection.close()

    def snapshot(self):
        return {name: self.request('/' + name) for name in ('configs', 'rules', 'proxies')}

    def reload(self, path):
        self.request('/configs?force=true', {'path': str(Path(path).absolute()), 'payload': ''})


def validate_socket(path):
    candidate = Path(path)
    if not candidate.is_absolute() or not hasattr(os, 'getuid'):
        raise ValueError('Unix 控制接口不可用')
    # /var on macOS is a system-owned alias to /private/var.
    candidate = candidate.resolve(strict=True)
    _safe(candidate)
    info = candidate.stat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in (0, os.getuid()):
        raise ValueError('Unix 控制接口归属无效')
    for parent in candidate.parents:
        mode = parent.stat()
        if mode.st_uid not in (0, os.getuid()) or mode.st_mode & 0o002 and not mode.st_mode & stat.S_ISVTX:
            raise ValueError('Unix 控制接口目录可被其他用户替换')
    return str(candidate)


def from_config(config, system=None):
    system = system or platform.system()
    secret = config.get('secret', '') or ''
    unix = config.get('external-controller-unix')
    if system == 'Darwin' and unix:
        if not isinstance(unix, str) or len(unix) > 1000:
            raise ValueError('Unix 控制接口格式无效')
        return LocalController(unix=validate_socket(unix), secret=secret)
    address = config.get('external-controller')
    if not isinstance(address, str) or not address or '://' in address:
        raise ValueError('请在 Clash Verge 启用本机 HTTP 控制接口')
    # Wildcard listeners are contacted only through literal loopback.
    for wildcard, loopback in (('0.0.0.0:', '127.0.0.1:'), ('[::]:', '[::1]:')):
        if address.startswith(wildcard):
            address = loopback + address[len(wildcard):]
    return LocalController(origin='http://' + address, secret=secret)


def discover(home=None, system=None, environ=None):
    env = os.environ if environ is None else environ
    if env.get('ENVSCOPE_CONTROLLER_URL'):
        return LocalController(origin=env['ENVSCOPE_CONTROLLER_URL'], secret=env.get('ENVSCOPE_CONTROLLER_SECRET', ''))
    candidates = {}
    for directory in config_directories(home, system, env):
        raw = _read(directory / 'clash-verge.yaml')
        if raw is not None:
            _, config = load_yaml(raw)
            controller = from_config(config, system)
            candidates[controller.identity] = controller
    if len(candidates) != 1:
        raise ValueError('未找到唯一的本机内核接口，请在客户端启用控制接口后复检')
    return next(iter(candidates.values()))
