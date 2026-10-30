"""Classify OS consent without equating command completion with a repair."""
import re
import subprocess

MESSAGES = {
    'consent_cancelled': '系统授权已取消。请刷新实际状态，已有事务仍需按恢复记录核对。',
    'policy_denied': '组织策略阻止了操作。请联系管理员处理，并保留恢复记录。',
    'permission_denied': '系统拒绝了所需权限。请核对授权及恢复记录。',
    'operation_failed': '系统操作未完成。请核对实际状态及恢复记录后再重试。',
    'execution_unknown': '等待系统操作超时，执行结果尚不确定。请先刷新状态及恢复记录，勿重复提交。',
}


class ConsentError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(MESSAGES[code])


def raise_for_consent(result, system):
    if result.returncode == 0:
        return
    stderr = result.stderr or ''
    if isinstance(stderr, bytes):
        stderr = stderr.decode('utf-8', errors='replace')
    # Only the osascript native error suffix, never the word "cancelled".
    mac_cancel = system == 'Darwin' and re.search(r'\(-128\)\s*$', stderr[-1024:])
    code = ('consent_cancelled' if system == 'Windows' and result.returncode == 1223 or mac_cancel else
            'policy_denied' if system == 'Windows' and result.returncode == 1260 else
            'permission_denied' if system == 'Windows' and result.returncode == 5 else 'operation_failed')
    raise ConsentError(code)


def operation_outcome(error):
    code = error.code if isinstance(error, ConsentError) else 'execution_unknown' if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)) else 'permission_denied' if isinstance(error, PermissionError) else 'operation_failed'
    return {'error': code, 'needs_retest': True}
