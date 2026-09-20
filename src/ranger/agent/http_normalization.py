"""Pure HTTP action normalization and authentication helpers."""

import base64
import binascii
import json
from typing import Any, Mapping
from urllib.parse import urlsplit

def prepare_http_action(raw: Mapping[str, Any], base_url: str) -> dict[str, Any]:
    """Make adapter-specific HTTP proposals one normalizer input shape."""
    prepared = dict(raw)
    arguments = raw.get("arguments") if isinstance(raw.get("arguments"), Mapping) else {}
    sources = [
        ("body", raw.get("body"), "body" in raw),
        ("json", raw.get("json"), "json" in raw),
        ("data", raw.get("data"), "data" in raw),
        ("arguments.body", arguments.get("body"), "body" in arguments),
        ("arguments.json", arguments.get("json"), "json" in arguments),
        ("arguments.data", arguments.get("data"), "data" in arguments),
    ]
    present = [(name, value) for name, value, exists in sources if exists]
    if len(present) > 1:
        prepared["_normalization_status"] = "unclassified"
    elif present:
        prepared["body"] = present[0][1]

    headers = raw.get("headers") if isinstance(raw.get("headers"), Mapping) else {}
    if not headers and isinstance(arguments.get("headers"), Mapping):
        headers = arguments["headers"]
    prepared["headers"] = dict(headers)
    content_type = (raw.get("content_type") or arguments.get("content_type")
                    or headers.get("Content-Type") or headers.get("content-type"))
    if content_type:
        prepared["content_type"] = content_type
    elif present and isinstance(present[0][1], Mapping):
        prepared["content_type"] = "application/json"

    method = raw.get("method", arguments.get("method", "GET"))
    prepared["method"] = str(method).upper()
    path = raw.get("path", arguments.get("path"))
    url = raw.get("url", raw.get("target_url", arguments.get("url")))
    if not isinstance(path, str) and isinstance(url, str):
        path = urlsplit(url).path or "/"
    if isinstance(path, str):
        prepared["path"] = path
        if isinstance(url, str) and urlsplit(url).netloc:
            prepared["url"] = url
        else:
            prepared["url"] = base_url.rstrip("/") + path
    elif isinstance(url, str):
        prepared["url"] = url
    else:
        prepared["_normalization_status"] = "unclassified"
    if isinstance(prepared.get("body"), Mapping):
        prepared["body"] = json.dumps(prepared["body"], ensure_ascii=False)
    return prepared


def _authentication_summary(body: str) -> str:
    """Return safe auth hints without exposing bearer tokens to the agent."""
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return ""

    def token_values(value: Any):
        if isinstance(value, Mapping):
            for key, child in value.items():
                if str(key).casefold() == "token" and isinstance(child, str):
                    yield child
                yield from token_values(child)
        elif isinstance(value, list):
            for child in value:
                yield from token_values(child)

    for token in token_values(document):
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            padding = "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
        except (ValueError, TypeError, json.JSONDecodeError, binascii.Error):
            continue
        data = claims.get("data") if isinstance(claims, Mapping) else None
        role = data.get("role") if isinstance(data, Mapping) else claims.get("role")
        if isinstance(role, str) and role:
            state = "admin_session_established" if role == "admin" else "authenticated_session_established"
            return f"authentication_role={role}\nauthentication_state={state}"
    return ""


def _redact_authentication_tokens(body: str) -> str:
    """Redact token fields from the body shown to the agent."""
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return body

    def redact(value: Any):
        if isinstance(value, Mapping):
            return {
                key: ("[redacted-token]" if str(key).casefold() == "token" else redact(child))
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [redact(child) for child in value]
        return value

    return json.dumps(redact(document), ensure_ascii=False)



