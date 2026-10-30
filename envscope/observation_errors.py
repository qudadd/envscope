"""Bounded failure evidence shared by read-only OS observations.

Never retain command output: it may contain private paths or credentials.
"""
import errno
import re
import subprocess

CODES = frozenset({'permission_denied', 'policy_denied', 'timeout', 'tool_missing',
                   'invalid_response', 'unavailable'})


class ObservationError(OSError):
    def __init__(self, code):
        self.code = code if code in CODES else 'unavailable'
        super().__init__(self.code)


def error_evidence(error, operation):
    code = getattr(error, 'code', None)
    if code not in CODES:
        if getattr(error, 'winerror', None) == 1260:
            code = 'policy_denied'
        elif isinstance(error, PermissionError) or getattr(error, 'errno', None) in (errno.EACCES, errno.EPERM) or getattr(error, 'winerror', None) == 5:
            code = 'permission_denied'
        elif isinstance(error, (subprocess.TimeoutExpired, TimeoutError)):
            code = 'timeout'
        elif isinstance(error, FileNotFoundError):
            code = 'tool_missing'
        elif isinstance(error, (ValueError, TypeError)):
            code = 'invalid_response'
        else:
            code = 'unavailable'
    # Operations are internal identifiers, not commands or user-supplied paths.
    name = operation if isinstance(operation, str) and re.fullmatch(r'[a-z_][a-z0-9_.-]{0,63}', operation) else 'observation'
    return {'error': code, 'operation': name}


def check_command(result, limit=262144):
    if result.returncode:
        stderr = result.stderr or ''
        if isinstance(stderr, bytes):
            stderr = stderr.decode('utf-8', errors='replace')
        stderr = stderr[:limit].lower()
        code = ('policy_denied' if result.returncode == 1260 or 'blocked by group policy' in stderr else
                'permission_denied' if any(value in stderr for value in
                    ('permission denied', 'operation not permitted', 'access is denied', 'access denied', 'unauthorizedaccessexception')) else
                'unavailable')
        raise ObservationError(code)
    if not isinstance(result.stdout, str) or len(result.stdout) > limit:
        raise ObservationError('invalid_response')


def inventory_errors(inventory, *components):
    """Normalize old and current collectors, optionally for dependent checks."""
    network = inventory.get('network', {})
    if not isinstance(network, dict):
        return {'inventory': error_evidence(ValueError(), 'inventory')}
    errors = {}
    for name, value in network.get('errors', {}).items() if isinstance(network.get('errors', {}), dict) else ():
        code = value.get('error') if isinstance(value, dict) else value
        errors[name] = error_evidence(ObservationError(code), name)
    for key, name in (('dns_error', 'dns'), ('default_route_error', 'routes')):
        if network.get(key):
            errors.setdefault(name, error_evidence(ObservationError(network[key]), name))
    if inventory.get('network_error'):
        value = inventory['network_error']
        errors['inventory'] = error_evidence(ObservationError(value.get('error') if isinstance(value, dict) else value), 'inventory')
    if components:
        return {name: value for name, value in errors.items() if name in components or name == 'inventory'}
    return errors
