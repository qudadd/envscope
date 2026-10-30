"""One strict identity/freshness check for native service and watchdog views."""
from . import __release__


def normalize_heartbeat(value, system):
    if system != 'Windows':
        return value
    result = dict(value)
    for key in ('format', 'guard_policy'):
        text = value.get(key)
        result[key] = int(text) if isinstance(text, str) and text in ('1', '2') else None
    for key in ('fixture', 'initial'):
        result[key] = {'0': False, '1': True}.get(value.get(key))
    try:
        result['at_epoch'] = float(value.get('at_epoch', 0))
    except (TypeError, ValueError):
        result['at_epoch'] = 0
    return result


def heartbeat_current(baseline, heartbeat, now, *, fixture=False):
    stamp = heartbeat.get('at_epoch')
    return (type(heartbeat.get('format')) is int and heartbeat['format'] == 1
            and type(heartbeat.get('guard_policy')) is int and heartbeat['guard_policy'] == 2
            and baseline.get('release') == __release__
            and heartbeat.get('release') == baseline.get('release')
            and bool(baseline.get('target')) and heartbeat.get('target') == baseline['target']
            and heartbeat.get('fixture') is fixture and heartbeat.get('initial') is False
            and type(stamp) in (int, float) and 0 <= now - stamp < 180)
