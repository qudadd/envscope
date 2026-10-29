"""Bounded, comment-preserving edits to a discovered Clash Verge configuration.

User scripts are data here: EnvScope never evaluates them. Runtime activation is
verified separately against the local core API.
"""
from io import StringIO
import json
import math
import re

from ruamel.yaml import YAML
from ruamel.yaml.events import AliasEvent, CollectionStartEvent, CollectionEndEvent

from .baseline import DOMAINS

LIMIT = 1048576
START = '// >>> envscope pinned rules >>>'
END = '// <<< envscope pinned rules <<<'
OLD_START = '// >>> claude-switcher managed rules >>>'
OLD_END = '// <<< claude-switcher managed rules <<<'


def plain(value, seen=None, depth=0, budget=None):
    seen = set() if seen is None else seen
    budget = [100000] if budget is None else budget
    budget[0] -= 1
    if depth > 40 or budget[0] < 0:
        raise ValueError('配置结构过深或过大，请在客户端处理')
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return float(value)
    if not isinstance(value, (dict, list)) or id(value) in seen:
        raise ValueError('配置包含无法安全修改的标签、循环引用或数据类型')
    seen.add(id(value))
    try:
        if isinstance(value, list):
            return [plain(v, seen, depth + 1, budget) for v in value]
        if any(not isinstance(k, str) for k in value):
            raise ValueError('配置键必须为文本')
        return {str(k): plain(v, seen, depth + 1, budget) for k, v in value.items()}
    finally:
        seen.remove(id(value))


def load_yaml(raw):
    if not isinstance(raw, bytes) or len(raw) > LIMIT:
        raise ValueError('未找到完整配置，或文件超过 1 MiB')
    try:
        text = raw.decode('utf-8-sig')
        yaml = YAML(typ='rt', pure=True)
        yaml.allow_duplicate_keys = False
        yaml.preserve_quotes = True
        yaml.max_depth = 40
        depth = aliases = count = 0
        open_anchors = []
        for event in yaml.parse(text):
            count += 1
            depth += isinstance(event, CollectionStartEvent) - isinstance(event, CollectionEndEvent)
            aliases += isinstance(event, AliasEvent)
            if isinstance(event, AliasEvent) and event.anchor in open_anchors:
                raise ValueError('cyclic YAML reference')
            if isinstance(event, CollectionStartEvent):
                open_anchors.append(event.anchor)
            elif isinstance(event, CollectionEndEvent):
                open_anchors.pop()
            tag = getattr(event, 'tag', None)
            if (count > 100000 or depth > 40 or aliases > 100 or
                    tag and tag not in ('tag:yaml.org,2002:str', 'tag:yaml.org,2002:int',
                                        'tag:yaml.org,2002:float', 'tag:yaml.org,2002:bool',
                                        'tag:yaml.org,2002:null', 'tag:yaml.org,2002:map', 'tag:yaml.org,2002:seq')):
                raise ValueError('unsupported YAML structure')
        value = yaml.load(text)
        if not isinstance(value, dict):
            raise ValueError('expected mapping')
        plain(value)
        return yaml, value
    except Exception as error:
        # Parser messages can include secrets from the input line.
        raise ValueError('配置无法安全解析：请检查重复键、多文档、标签或过深引用；未执行写入') from error


def rule_strings(group, policy):
    if (not isinstance(group, str) or not group or len(group) > 100 or
            any(c in ',()\r\n' or ord(c) < 32 or ord(c) == 127 for c in group) or
            group.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'GLOBAL') or
            policy not in ('proxy', 'reject')):
        raise ValueError('请选择明确的代理组与 UDP 策略；组名不能含规则分隔符')
    udp = 'REJECT' if policy == 'reject' else group
    return [f'AND,((NETWORK,UDP),(DST-PORT,{p})),{udp}' for p in (3478, 5349, 19302)] + [
        f'DOMAIN-SUFFIX,{domain},{group}' for domain in DOMAINS]


def update_yaml_rules(raw, pinned):
    yaml, config = load_yaml(raw)
    before = plain(config)
    rules = config.get('rules', [])
    if not isinstance(rules, list) or any(not isinstance(r, str) for r in rules):
        raise ValueError('运行配置 rules 不是规则文本列表')
    desired = pinned + [r for r in rules if r not in pinned]
    if list(rules) == desired:
        return raw
    config['rules'] = desired
    output = StringIO()
    yaml.dump(config, output)
    result = output.getvalue().encode('utf-8')
    if raw.startswith(b'\xef\xbb\xbf'):
        result = b'\xef\xbb\xbf' + result
    _, checked = load_yaml(result)
    after = plain(checked)
    before.pop('rules', None)
    after.pop('rules', None)
    if after != before or list(checked['rules']) != desired:
        raise ValueError('无法保证仅修改 rules；未执行写入')
    return result


def _remove_block(source, start, end):
    if start not in source and end not in source:
        return source
    pattern = re.compile(r'(?m)^' + re.escape(start) + r'\r?\n[\s\S]*?^' + re.escape(end) + r'(?:\r?\n|$)')
    if source.count(start) != 1 or source.count(end) != 1 or not pattern.search(source):
        raise ValueError('发现重复或不完整的托管脚本标记，请先在客户端核对，未覆盖用户脚本')
    return pattern.sub('', source, count=1)


def update_script(raw, group, pinned):
    if raw is None:
        raise ValueError('全局脚本文件缺失，请先在 Clash Verge 中初始化全局扩展脚本')
    try:
        source = raw.decode('utf-8-sig')
    except UnicodeError as error:
        raise ValueError('全局脚本编码无法识别') from error
    source = _remove_block(_remove_block(source, START, END), OLD_START, OLD_END)
    # The documented entry point is a function declaration. Other syntaxes need
    # review in the client's editor; do not guess or execute arbitrary JS here.
    if not re.search(r'(?m)^\s*function\s+main\s*\(', source):
        raise ValueError('请在客户端确认全局脚本包含 function main(config)；此写法不能自动组合')
    block = '\n' + START + '\n;(function () {\n' + \
        '  const originalMain = main;\n' + \
        '  const group = ' + json.dumps(group, ensure_ascii=True) + ';\n' + \
        '  const pinned = ' + json.dumps(pinned, ensure_ascii=True) + ';\n' + \
        '  main = function (...args) {\n' + \
        '    const result = originalMain.apply(this, args);\n' + \
        '    if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("EnvScope: main must return config");\n' + \
        '    if (!Array.isArray(result["proxy-groups"]) || !result["proxy-groups"].some(g => g && g.name === group)) throw new Error("EnvScope: proxy group missing");\n' + \
        '    if (result.rules !== undefined && !Array.isArray(result.rules)) throw new Error("EnvScope: rules must be array");\n' + \
        '    result.rules = pinned.concat((result.rules || []).filter(rule => !pinned.includes(rule)));\n' + \
        '    return result;\n  };\n})();\n' + END + '\n'
    result = (source.rstrip('\r\n') + block).encode('utf-8')
    if raw.startswith(b'\xef\xbb\xbf'):
        result = b'\xef\xbb\xbf' + result
    if len(result) > LIMIT:
        raise ValueError('组合后的脚本超过 1 MiB')
    return result
