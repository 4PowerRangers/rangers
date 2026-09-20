"""Target-independent HTTP tool skills used by Capability v2-C."""

from __future__ import annotations

import base64
import copy
import html
import json
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Mapping
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class ToolSkill:
    id: str
    name: str
    family: str
    prerequisites: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    output_expectations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParameterMutation:
    location: str
    key: str
    value: Any
    strategy: str = "controlled_variation"


@dataclass(frozen=True)
class ResponseDiff:
    status_changed: bool
    from_status: int | None
    to_status: int | None
    body_size_delta: int
    new_json_keys: tuple[str, ...]
    removed_json_keys: tuple[str, ...]
    content_type_changed: bool
    redirect_changed: bool
    auth_state_changed: bool
    error_signals_changed: bool
    marker_changed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_changed": self.status_changed,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "body_size_delta": self.body_size_delta,
            "new_json_keys": list(self.new_json_keys),
            "removed_json_keys": list(self.removed_json_keys),
            "content_type_changed": self.content_type_changed,
            "redirect_changed": self.redirect_changed,
            "auth_state_changed": self.auth_state_changed,
            "error_signals_changed": self.error_signals_changed,
            "marker_changed": self.marker_changed,
        }


@dataclass(frozen=True)
class EndpointCandidate:
    path: str
    external: bool = False
    priority: int = 1


SKILLS = (
    ToolSkill("HTTP_REQUEST", "HTTP request", "http", capabilities=("send_request",)),
    ToolSkill("HTTP_SESSION_REQUEST", "HTTP session request", "http", prerequisites=("session_artifact",), capabilities=("reuse_cookie", "reuse_token")),
    ToolSkill("PARAMETER_MUTATION", "Parameter mutation", "mutation", prerequisites=("base_request",), capabilities=("change_one_field",)),
    ToolSkill("HEADER_MUTATION", "Header mutation", "mutation", capabilities=("change_one_header",)),
    ToolSkill("JSON_BODY_MUTATION", "JSON body mutation", "mutation", capabilities=("change_json_field",)),
    ToolSkill("FORM_BODY_MUTATION", "Form body mutation", "mutation", capabilities=("change_form_field",)),
    ToolSkill("TOKEN_EXTRACT", "Token extraction", "extraction", capabilities=("extract_token",)),
    ToolSkill("COOKIE_EXTRACT", "Cookie extraction", "extraction", capabilities=("extract_cookie",)),
    ToolSkill("JWT_DECODE", "JWT decode", "analysis", prerequisites=("jwt_artifact",), capabilities=("decode_without_verification",)),
    ToolSkill("ENCODE_DECODE", "Encoding transform", "utility", capabilities=("url", "base64", "base64url", "hex", "json", "html")),
    ToolSkill("RESPONSE_COMPARE", "Response comparison", "analysis", prerequisites=("baseline", "variant"), capabilities=("compare_response" ,)),
    ToolSkill("ENDPOINT_EXTRACT", "Endpoint extraction", "extraction", capabilities=("extract_endpoint",)),
    ToolSkill("LINK_EXTRACT", "Link extraction", "extraction", capabilities=("extract_link",)),
    ToolSkill("JSON_FIELD_EXTRACT", "JSON field extraction", "extraction", capabilities=("summarize_json",)),
)
SKILL_BY_ID = {skill.id: skill for skill in SKILLS}


def extract_cookies(response: Any) -> dict[str, str]:
    """Parse Set-Cookie headers, preserving only cookie name/value pairs."""
    headers = response.get("headers", {}) if isinstance(response, Mapping) else {}
    values = [value for key, value in headers.items() if str(key).casefold() == "set-cookie"]
    if isinstance(response, str):
        values = re.findall(r"(?im)^set-cookie:\s*([^\n]+)", response)
    result: dict[str, str] = {}
    for value in values:
        cookie = SimpleCookie()
        cookie.load(value)
        result.update({key: morsel.value for key, morsel in cookie.items()})
    return result


def _token_like(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 8:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-.~+/=]{8,}", value))


def extract_tokens(response: Any) -> dict[str, str]:
    """Extract token-shaped values from JSON and authorization-like headers."""
    headers = response.get("headers", {}) if isinstance(response, Mapping) else {}
    body = response.get("body", "") if isinstance(response, Mapping) else response
    if isinstance(body, str) and "body=" in body:
        body = body.split("body=", 1)[1].strip()
    result: dict[str, str] = {}
    for key, value in headers.items():
        if str(key).casefold() in {"authorization", "x-auth-token", "x-access-token"} and _token_like(str(value)):
            result[str(key)] = str(value).removeprefix("Bearer ").strip()
    try:
        parsed = body if isinstance(body, (dict, list)) else json.loads(str(body))
    except (TypeError, ValueError):
        parsed = None

    def walk(value: Any, path: str = "") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                name = str(key)
                if name.casefold() in {"access_token", "token", "jwt", "session", "auth"} and _token_like(child):
                    result[path + name] = child
                walk(child, path + name + ".")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}{index}.")

    walk(parsed)
    return result


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode JWT header/payload only; never claim signature validity."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain three segments")

    def decode_part(value: str) -> Any:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return json.loads(raw.decode("utf-8"))

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    if not isinstance(header, Mapping) or not isinstance(payload, Mapping):
        raise ValueError("JWT header and payload must be JSON objects")
    return {
        "alg": header.get("alg"), "header_keys": sorted(map(str, header)),
        "payload_keys": sorted(map(str, payload)), "claims": dict(payload), "verified": False,
    }


def build_session_request(method: str, url: str, memory: Any, *, headers: Mapping[str, str] | None = None,
                          body: Any = None) -> dict[str, Any]:
    """Build a request using stored session artifacts only when explicitly called."""
    result = {"method": method.upper(), "url": url, "headers": dict(headers or {})}
    cookies = getattr(memory, "cookies", {}) or {}
    if cookies and "Cookie" not in result["headers"]:
        result["headers"]["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
    tokens = getattr(memory, "session_tokens", {}) or {}
    if tokens and "Authorization" not in result["headers"]:
        result["headers"]["Authorization"] = f"Bearer {next(iter(tokens.values()))}"
    if body is not None:
        result["body"] = body
    return result


def mutate_request(base_request: Mapping[str, Any], mutations: list[ParameterMutation]) -> dict[str, Any]:
    """Apply bounded, one-variable mutations to a request copy."""
    request = copy.deepcopy(dict(base_request))
    for mutation in mutations:
        location, key, value = mutation.location.casefold(), mutation.key, mutation.value
        if location == "query":
            parsed = urlsplit(str(request.get("url", request.get("path", ""))))
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[key] = str(value)
            updated = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))
            request["url"] = updated
            if "path" in request and not parsed.scheme and not parsed.netloc:
                request["path"] = updated
        elif location == "path":
            field = str(request.get("path", request.get("url", "")))
            segments = field.split("/")
            index = int(key) if key.isdigit() and int(key) < len(segments) else len(segments) - 1
            segments[index] = str(value)
            request["path"] = "/".join(segments)
            if "url" in request and not urlsplit(str(request["url"])).scheme:
                request["url"] = request["path"]
        elif location == "header":
            request.setdefault("headers", {})[key] = str(value)
        elif location in {"json", "json_body"}:
            body = request.setdefault("body", {})
            if not isinstance(body, Mapping):
                raise ValueError("JSON body mutation requires a mapping body")
            body[key] = value
        elif location in {"form", "form_body"}:
            body = dict(parse_qsl(str(request.get("body", "")), keep_blank_values=True))
            body[key] = str(value)
            request["body"] = urlencode(body)
        else:
            raise ValueError(f"unsupported mutation location: {mutation.location}")
    return request


def _response_facts(response: Any) -> dict[str, Any]:
    if isinstance(response, Mapping):
        body = response.get("body", "")
        status = response.get("status")
        headers = response.get("headers", {})
    else:
        text = str(response)
        match = re.search(r"(?:^|\n)status=(\d{3})", text)
        status = int(match.group(1)) if match else None
        body = text
        headers = {}
        if "body=" in body:
            body = body.split("body=", 1)[1].strip()
    try:
        parsed = body if isinstance(body, Mapping) else json.loads(str(body))
    except (TypeError, ValueError):
        parsed = None
    return {
        "status": status, "size": len(str(body)),
        "keys": tuple(sorted(parsed)) if isinstance(parsed, Mapping) else (),
        "content_type": next((v for k, v in headers.items() if str(k).casefold() == "content-type"), None),
        "location": next((v for k, v in headers.items() if str(k).casefold() == "location"), None),
        "auth": "unauthorized" in str(body).casefold() or status in {401, 403},
        "error": "error" in str(body).casefold(),
        "marker": bool(re.search(r"(?i)(reflection|goal_state|realized_outcome)", str(body))),
    }


def compare_responses(a: Any, b: Any) -> ResponseDiff:
    left, right = _response_facts(a), _response_facts(b)
    return ResponseDiff(
        status_changed=left["status"] != right["status"], from_status=left["status"], to_status=right["status"],
        body_size_delta=right["size"] - left["size"],
        new_json_keys=tuple(key for key in right["keys"] if key not in left["keys"]),
        removed_json_keys=tuple(key for key in left["keys"] if key not in right["keys"]),
        content_type_changed=left["content_type"] != right["content_type"],
        redirect_changed=left["location"] != right["location"], auth_state_changed=left["auth"] != right["auth"],
        error_signals_changed=left["error"] != right["error"], marker_changed=left["marker"] != right["marker"],
    )


def extract_endpoints(response: Any) -> tuple[str, ...]:
    text = str(response.get("body", "") if isinstance(response, Mapping) else response)
    pattern = r"(?:https?://[^\"'()\s]+|/(?:api|rest|graphql|v\d+)[A-Za-z0-9_./?=&:%{}-]*)"
    return tuple(dict.fromkeys(unquote(value) for value in re.findall(pattern, text, re.I)))


def extract_endpoint_candidates(response: Any, *, same_origin: str | None = None) -> tuple[EndpointCandidate, ...]:
    """Classify extracted links without crawling or following them."""
    static_suffixes = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff2")
    origin = urlsplit(same_origin).netloc if same_origin else None
    candidates = []
    for value in extract_endpoints(response):
        parsed = urlsplit(value)
        external = bool(parsed.netloc and parsed.netloc != origin)
        priority = 0 if parsed.path.casefold().endswith(static_suffixes) else 1
        candidates.append(EndpointCandidate(value, external, priority))
    return tuple(candidates)


def extract_json_fields(value: Any) -> dict[str, Any]:
    try:
        document = value if isinstance(value, (Mapping, list)) else json.loads(str(value))
    except (TypeError, ValueError):
        return {"top_level_keys": (), "nested_paths": (), "id_fields": (), "pagination_fields": (), "token_fields": ()}
    paths: list[str] = []
    id_fields: list[str] = []
    tokens: list[str] = []

    def walk(node: Any, path: str = "") -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                current = f"{path}.{key}" if path else str(key)
                paths.append(current)
                lower = str(key).casefold()
                if lower == "id" or lower.endswith("id"):
                    id_fields.append(current)
                if lower in {"token", "access_token", "jwt", "session"}:
                    tokens.append(current)
                walk(child, current)
        elif isinstance(node, list):
            for index, child in enumerate(node[:20]):
                walk(child, f"{path}[{index}]")

    walk(document)
    return {
        "top_level_keys": tuple(map(str, document.keys())) if isinstance(document, Mapping) else (),
        "nested_paths": tuple(dict.fromkeys(paths)), "id_fields": tuple(dict.fromkeys(id_fields)),
        "pagination_fields": tuple(path for path in paths if path.rsplit(".", 1)[-1].casefold() in {"page", "limit", "offset", "total", "next"}),
        "token_fields": tuple(dict.fromkeys(tokens)),
    }


def transform_value(value: str, *, operation: str) -> str:
    if operation == "url_encode":
        return quote(value, safe="")
    if operation == "url_decode":
        return unquote(value)
    if operation in {"base64_encode", "base64url_encode"}:
        encoded = base64.urlsafe_b64encode(value.encode()).decode() if operation.startswith("base64url") else base64.b64encode(value.encode()).decode()
        return encoded.rstrip("=") if operation.startswith("base64url") else encoded
    if operation in {"base64_decode", "base64url_decode"}:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    if operation == "hex_encode":
        return value.encode().hex()
    if operation == "hex_decode":
        return bytes.fromhex(value).decode()
    if operation == "json_escape":
        return json.dumps(value, ensure_ascii=False)[1:-1]
    if operation == "html_decode":
        return html.unescape(value)
    raise ValueError(f"unsupported transform operation: {operation}")


def recommend_tool_skills(*, signals: Any = (), hypothesis_family: str | None = None) -> tuple[str, ...]:
    signal_set = set(signals or ())
    selected: list[str] = []
    if "jwt_present" in signal_set:
        selected.append("JWT_DECODE")
    if "session_cookie" in signal_set:
        selected.append("COOKIE_EXTRACT")
    if hypothesis_family == "authorization" or "object_identifier" in signal_set:
        selected.extend(("PARAMETER_MUTATION", "RESPONSE_COMPARE"))
    if "reflection_signal" in signal_set:
        selected.extend(("PARAMETER_MUTATION", "RESPONSE_COMPARE"))
    if "api_object_surface" in signal_set:
        selected.append("JSON_FIELD_EXTRACT")
    if "discovered_endpoint" in signal_set:
        selected.append("ENDPOINT_EXTRACT")
    if not selected:
        selected.append("HTTP_REQUEST")
    return tuple(dict.fromkeys(selected))


def offline_tool_metrics() -> dict[str, Any]:
    """Run small provider-free fixtures for the tool layer."""
    token_ok = extract_tokens('status=200 body={"access_token":"abc.DEF-1234"}').get("access_token") == "abc.DEF-1234"
    cookie_ok = extract_cookies("Set-Cookie: session=abc; Path=/\n").get("session") == "abc"
    expected = {"/api/items", "/rest/users"}
    endpoint_values = extract_endpoints('<a href="/api/items">x</a> /rest/users')
    endpoint_ok = set(endpoint_values) == expected
    diff = compare_responses("status=403\nbody={\"error\":1}", "status=200\nbody={\"data\":1}")
    diff_ok = diff.status_changed and diff.new_json_keys == ("data",)
    mutation = mutate_request({"method": "GET", "path": "/api/item/1"}, [ParameterMutation("path", "id", "2")])
    mutation_ok = mutation["path"] == "/api/item/2"
    return {
        "token_extraction_accuracy": float(token_ok),
        "cookie_extraction_accuracy": float(cookie_ok),
        "endpoint_extraction_precision": float(endpoint_ok),
        "endpoint_extraction_recall": float(endpoint_ok),
        "response_diff_correctness": float(diff_ok),
        "mutation_correctness": float(mutation_ok),
        "determinism": endpoint_values == extract_endpoints('<a href="/api/items">x</a> /rest/users'),
    }