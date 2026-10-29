"""Append-only local event files; UI history limits never delete these records."""
import json
import os
from pathlib import Path
import stat
from .accounts import _safe_chain


def append_event(root, event):
    root=Path(root);_safe_chain(root);root.mkdir(parents=True,exist_ok=True,mode=0o700)
    name=event['at'][:10]
    from datetime import date
    date.fromisoformat(name)
    path=root/(name+'.private.jsonl');_safe_chain(path)
    payload=(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')
    if len(payload)>65536:raise ValueError('事件过大，未写入守护日志')
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),0o600)
    with os.fdopen(fd,'ab') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('事件日志路径不安全')
        stream.write(payload);stream.flush();os.fsync(stream.fileno())
