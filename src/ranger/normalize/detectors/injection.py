import json
from collections.abc import Mapping
from urllib.parse import parse_qs


_CREDENTIAL_FIELDS = {
    ("POST", "/rest/user/login", "email"): "credential_literal",
    ("POST", "/rest/user/login", "password"): "credential_literal",
}
_CREDENTIAL_ENDPOINTS = {(method, path) for method, path, _field in _CREDENTIAL_FIELDS}


def resolve_field_role(method: str, path: str | None, field: str) -> str | None:
    return _CREDENTIAL_FIELDS.get((method, path or "", field))


def parse_http_body(content_type: str | None, body: object, *,
                    method: str | None = None, path: str | None = None) -> tuple[dict[str, object] | None, str | None]:
    if body is None:
        return None, None
    if not content_type:
        return None, None
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            return None, "ambiguous"
    if not isinstance(body, str):
        return None, "ambiguous"
    media_type = str(content_type or "").split(";", 1)[0].strip().casefold()
    if media_type == "application/json":
        try:
            value = json.loads(body)
        except (TypeError, ValueError):
            return None, "ambiguous"
        if not isinstance(value, Mapping):
            return None, "ambiguous"
        if (method, path) in _CREDENTIAL_ENDPOINTS and any(
            isinstance(item, (Mapping, list)) for item in value.values()
        ):
            return None, "ambiguous"
        return _flatten_json_object(value), None
    if media_type == "application/x-www-form-urlencoded":
        return {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}, None
    return None, "ambiguous"


def _flatten_json_object(value: Mapping[str, object]) -> dict[str, object]:
    return {
        str(key): item for key, item in value.items()
        if not isinstance(item, (Mapping, list))
    }


def detect_injection(*, method: str, path: str | None, content_type: object, body: object) -> dict[str, object]:
    parsed, status = parse_http_body(
        content_type if isinstance(content_type, str) else None, body, method=method, path=path,
    )
    if status:
        return {"classified": False, "status": status}
    if parsed is None:
        return {"classified": False, "status": "normal"}
    candidates = []
    structured_values = []
    for field, value in parsed.items():
        if value is None or not isinstance(value, (str, int, float, bool)):
            return {"classified": False, "status": "ambiguous"}
        value = str(value)
        signals = _sql_structure(value)
        if signals:
            structured_values.append(signals)
        if resolve_field_role(method, path, str(field)) != "credential_literal":
            continue
        if signals:
            candidates.append(signals)
    if len(candidates) > 1:
        return {"classified": False, "status": "ambiguous"}
    if candidates:
        return {
            "classified": True,
            "status": "normalized",
            "intent": "exploit_test",
            "attack_family": "sql_injection",
            "signals": candidates[0],
        }
    if structured_values:
        return {"classified": False, "status": "ambiguous"}
    return {"classified": False, "status": "normal"}


def _sql_structure(value: str) -> list[str]:
    tokens = _tokens(value)
    if not tokens:
        return []
    operators = {"=", "!=", "<>", "<", ">", "<=", ">=", "LIKE"}
    boolean = {"AND", "OR"}
    has_comparison = any(token in operators for token in tokens)
    has_boolean = any(token in boolean for token in tokens)
    quoted = sum(token == "QUOTE" for token in tokens)
    has_control = any(token in {"COMMENT", ";"} for token in tokens)
    if quoted >= 2 and has_comparison:
        signals = ["comparison_expression", "quoted_operands"]
        if has_boolean:
            signals.append("boolean_connective")
        if has_control:
            signals.append("syntactic_control")
        return signals
    if has_boolean and has_comparison and quoted >= 1:
        return ["boolean_connective", "comparison_expression"]
    return []


def _tokens(value: str) -> list[str]:
    tokens: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char.isspace():
            index += 1
        elif char in "'\"":
            tokens.append("QUOTE")
            index += 1
        elif value.startswith("--", index):
            tokens.append("COMMENT")
            index += 2
        elif value[index:index + 2] in {"!=", "<>", "<=", ">="}:
            tokens.append(value[index:index + 2])
            index += 2
        elif char in "=<>;":
            tokens.append(char)
            index += 1
        else:
            end = index + 1
            while end < len(value) and (value[end].isalnum() or value[end] in "_.$@-%"):
                end += 1
            word = value[index:end]
            tokens.append(word.upper() if word.casefold() in {"and", "or", "like"} else word)
            index = end
    return tokens