"""Edit only the GUI-owned Clash Verge TUN preference, never evaluate scripts."""
from io import StringIO

from .routing_config import load_yaml,plain

TUN_KEY='enable_tun_mode'


def tun_model(raw):
    _,value=load_yaml(raw)
    if getattr(value,'merge',None):
        raise ValueError('TUN 偏好使用了 YAML 合并键，请在客户端手动设置，未覆盖继承配置')
    present=TUN_KEY in value
    before=value.get(TUN_KEY)
    if before is not None and type(before) is not bool:
        raise ValueError('TUN 开关不是布尔值或未指定状态，请在客户端手动核对')
    return {'present':present,'value':before}


def validate_model(value):
    if (not isinstance(value,dict) or set(value)!={'present','value'} or type(value['present']) is not bool
            or value['value'] is not None and type(value['value']) is not bool
            or value['present'] is False and value['value'] is not None):
        raise ValueError('TUN 原值记录无效，保留备份并手动核对')
    return value


def update_tun(raw,model):
    validate_model(model);before=tun_model(raw)
    if before==model:return raw
    yaml,value=load_yaml(raw)
    unrelated={k:plain(v) for k,v in value.items() if k!=TUN_KEY}
    if model['present']:value[TUN_KEY]=model['value']
    else:value.pop(TUN_KEY,None)
    out=StringIO();yaml.dump(value,out)
    data=out.getvalue().encode('utf-8')
    if raw.startswith(b'\xef\xbb\xbf'):data=b'\xef\xbb\xbf'+data
    _,after=load_yaml(data)
    if tun_model(data)!=model or {k:plain(v) for k,v in after.items() if k!=TUN_KEY}!=unrelated:
        raise ValueError('TUN 写入结果或其他字段未能核对，未生成配置')
    return data
