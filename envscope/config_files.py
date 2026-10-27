"""Secret-free configuration diagnostics and narrowly defined JSON edits."""
import json


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("nonstandard_number")


def load_object(text):
    return json.loads(text, object_pairs_hook=_unique, parse_constant=_invalid_constant)


def remove_trailing_commas(text):
    """Remove only commas immediately before a closing bracket outside strings."""
    positions, quoted, escaped = set(), False, False
    for i, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ',':
            j = i + 1
            while j < len(text) and text[j].isspace():
                j += 1
            if j < len(text) and text[j] in '}]':
                positions.add(i)
    candidate = ''.join(c for i, c in enumerate(text) if i not in positions)
    if not positions:
        return None
    try:
        value = load_object(candidate)
    except (ValueError, RecursionError):
        return None
    return candidate if isinstance(value, dict) else None


def inspect_text(text):
    try:
        data = load_object(text)
    except json.JSONDecodeError as error:
        hints = {"Expecting property name enclosed in double quotes": "属性名需要双引号，或上一项多写了逗号",
                 "Expecting ',' delimiter": "项目之间缺少逗号，或括号没有正确闭合",
                 "Expecting value": "此处缺少有效的 JSON 值", "Extra data": "根对象后还有多余内容",
                 "Unterminated string starting at": "字符串缺少结束双引号"}
        return {"valid": False, "error": "json_syntax", "line": error.lineno, "column": error.colno,
                "explanation": hints.get(error.msg, "JSON 语法不完整，请检查引号、逗号和括号"),
                "repairable": "trailing_comma" if remove_trailing_commas(text) is not None else None}
    except (ValueError, RecursionError):
        return {"valid": False, "error": "unsafe_json", "explanation": "存在重复字段、非标准数值或过深结构，不能确定原意并自动覆盖"}
    if not isinstance(data, dict):
        return {"valid": False, "error": "root_not_object", "explanation": "最外层必须是以花括号包围的 JSON 对象"}
    for key in ("mcpServers", "env"):
        if key in data and not isinstance(data[key], dict):
            return {"valid": False, "error": "invalid_" + key, "explanation": key + " 必须是 JSON 对象"}
    if any(not isinstance(v, str) for v in data.get("env", {}).values()):
        return {"valid": False, "error": "invalid_env_value", "explanation": "env 中的环境变量值必须是字符串"}
    return {"valid": True, "mcp_server_count": len(data.get("mcpServers", {}))}
