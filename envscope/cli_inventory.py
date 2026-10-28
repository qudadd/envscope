"""Bounded passive CLI provenance; never run a discovered executable."""
import json
import os
from pathlib import Path


def installation_details(home, path=None):
    home = Path(home)
    search = os.environ.get('PATH','') if path is None else path
    installations, seen = [], set()
    for directory in search.split(os.pathsep)[:256]:
        if not directory or not Path(directory).is_absolute():
            continue
        for name in ('claude','claude.exe','claude.cmd','claude.bat'):
            candidate = Path(directory)/name
            try:
                if not candidate.is_file():
                    continue
                real = candidate.resolve(strict=True)
                if str(real).casefold() in seen:
                    continue
                seen.add(str(real).casefold())
                text = str(real).replace('\\','/').lower()
                method = 'Homebrew' if '/cellar/' in text or '/homebrew/' in text else 'npm / bun' if '/node_modules/' in text or '/npm/' in text or '/.bun/' in text else '原生安装候选' if '/.local/' in text else '未知'
                version = None
                for base in (candidate.parent, real.parent, real.parent.parent):
                    for metadata in (base/'package.json',base/'node_modules/@anthropic-ai/claude-code/package.json'):
                        if metadata.is_file() and metadata.stat().st_size < 65536:
                            data = json.loads(metadata.read_text(encoding='utf-8'))
                            if data.get('name') == '@anthropic-ai/claude-code' and isinstance(data.get('version'),str) and len(data['version'])<80:
                                version = data['version']
                                method = 'npm / bun 元数据'
                installations.append({'path':str(candidate),'real_path':str(real),'method':method,'version':version})
            except (OSError, ValueError, RuntimeError):
                continue
    total, complete, visited = 0, True, 0
    todo = [home/'.claude']
    while todo:
        directory = todo.pop()
        try:
            if directory.is_symlink() or not directory.is_dir():
                continue
            for entry in directory.iterdir():
                visited += 1
                if visited > 20000:
                    complete = False
                    todo.clear()
                    break
                if entry.is_symlink() or getattr(entry.lstat(),'st_file_attributes',0)&0x400:
                    complete = False
                elif entry.is_dir():
                    todo.append(entry)
                elif entry.is_file():
                    total += entry.stat().st_size
        except OSError:
            complete = False
    rows = [{'label':'PATH 独立入口','value':str(len(installations))+('，发现多入口，请核对常用终端实际使用哪个版本' if len(installations)>1 else '，未运行入口程序')},
            {'label':'Code 目录已统计体积','value':f'{total/1024**2:.1f} MiB'+('（达到上限、不可读或含链接，仅部分统计）' if not complete else '')}]
    for item in installations:
        rows.append({'label':item['method'],'value':item['path']+' → '+item['real_path']+'；版本 '+(item['version'] or '元数据未提供，请在自己的终端执行 claude --version')})
    return {'installations':installations,'config_bytes':total,'size_complete':complete,'rows':rows}
