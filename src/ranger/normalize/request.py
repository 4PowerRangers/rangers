from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

_SENSITIVE = ("password", "token", "secret", "credential", "authorization", "cookie", "api_key", "apikey")
_SQL_MARKERS = ("injection_operator_pattern", "quoted_operand_pattern", "comment_pattern")
_SQL_RE = re.compile(r"(?:'|\")\s*(?:or|and)\s+[^\s=]+\s*=\s*[^\s]+|\bunion\s+select\b", re.I)
ACTIVITY_TAXONOMY = frozenset({
    "discovery", "authentication", "authorized_data_read", "sql_injection_testing",
    "credential_use", "credential_recovery", "password_cracking", "token_inspection",
    "token_forgery", "resource_modification", "resource_deletion", "report_submission",
    "post_goal_exploration",
})


def _sensitive(name: Any) -> bool:
    value = str(name).casefold().replace("-", "_")
    return any(word in value for word in _SENSITIVE)


def _safe(value: Any, name: Any = "") -> Any:
    if _sensitive(name):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(key): _safe(item, key) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe(item) for item in value]
    return value


def _fingerprint(value: Any) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def _parse_body(content_type: str | None, body: Any) -> tuple[Any, dict[str, Any] | None, str]:
    if body is None or body == b"" or body == "":
        return None, None, "absent"
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            return None, None, "unclassified"
    if not isinstance(body, str):
        return None, None, "unclassified"
    media_type = (content_type or "").split(";", 1)[0].strip().casefold()
    if media_type == "application/json":
        try:
            value = json.loads(body)
        except (TypeError, ValueError):
            return None, None, "unclassified"
        if not isinstance(value, Mapping):
            return None, None, "unclassified"
        return _safe(value), dict(value), "normalized"
    if media_type == "application/x-www-form-urlencoded":
        parsed = {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}
        return _safe(parsed), parsed, "normalized"
    if media_type == "text/plain":
        safe_text = re.sub(
            r"(?i)(\b(?:password|token|secret|credential)\s*[=:]\s*)[^&\s]+",
            r"\1[REDACTED]", body,
        )
        return safe_text, {"_text": body}, "normalized"
    return None, None, "unclassified"


def _values(request: Mapping[str, Any], parsed_body: Mapping[str, Any] | None) -> list[str]:
    values = [str(value) for value in (request.get("query") or {}).values()]
    if parsed_body:
        values.extend(str(value) for value in parsed_body.values())
    return values


def _sql_evidence(values: list[str]) -> list[str]:
    markers: set[str] = set()
    for value in values:
        if _SQL_RE.search(value):
            markers.update(_SQL_MARKERS[:2])
            if "--" in value or ";" in value:
                markers.add("comment_pattern")
    return sorted(markers)


def normalize_request(raw: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Return a stable request record without persisting raw credentials."""
    if not isinstance(raw, Mapping):
        return {"normalization_status": "unclassified", "body_parse_status": "unclassified"}
    url = raw.get("url") or raw.get("target_url") or raw.get("target")
    parsed = urlsplit(url) if isinstance(url, str) and "://" in url else None
    path_and_query = raw.get("path") or (parsed.path if parsed else "/") or "/"
    if isinstance(path_and_query, str) and "?" in path_and_query:
        path, embedded_query = path_and_query.split("?", 1)
    else:
        path, embedded_query = path_and_query, (parsed.query if parsed else "")
    query_raw = raw.get("query", embedded_query)
    if isinstance(query_raw, Mapping):
        query = {str(key): _safe(value, key) for key, value in query_raw.items()}
        query_for_detection = dict(query_raw)
    else:
        query_for_detection = {key: values[-1] for key, values in parse_qs(str(query_raw or ""), keep_blank_values=True).items()}
        query = {key: _safe(value, key) for key, value in query_for_detection.items()}
    headers_raw = raw.get("headers") if isinstance(raw.get("headers"), Mapping) else {}
    headers = {str(key).lower(): _safe(value, key) for key, value in headers_raw.items()}
    content_type = (raw.get("content_type") or raw.get("Content-Type")
                    or headers.get("content-type"))
    body, body_for_detection, body_status = _parse_body(content_type, raw.get("body", raw.get("_request_body")))
    detection_request = {"query": query_for_detection}
    markers = _sql_evidence(_values(detection_request, body_for_detection)) if body_status != "unclassified" else []
    body_fingerprints = {}
    if body_for_detection:
        for key, value in body_for_detection.items():
            if _sensitive(key):
                body_fingerprints[str(key)] = _fingerprint(value)
    result = {
        "method": str(raw.get("method", "GET")).upper(),
        "scheme": (raw.get("scheme") or (parsed.scheme if parsed else None)),
        "host": raw.get("host") or (parsed.hostname if parsed else None),
        "port": raw.get("port") or (parsed.port if parsed else None),
        "path": path or "/",
        "query": query,
        "headers": headers,
        "body": body,
        "body_fields": body if isinstance(body, Mapping) else None,
        "body_fingerprints": body_fingerprints,
        "content_type": content_type,
        "body_parse_status": body_status,
        "operation": {"GET": "READ", "POST": "CREATE", "PUT": "MODIFY",
                       "PATCH": "MODIFY", "DELETE": "DELETE"}.get(str(raw.get("method", "GET")).upper()),
        "evidence_markers": markers,
        "normalization_status": "unclassified" if body_status == "unclassified" else "normalized",
    }
    result["activity_classification"] = "unclassified" if body_status == "unclassified" else "classified"
    return result


def classify_activity(normalized_request: Mapping[str, Any],
                      scenario_context: Mapping[str, Any] | None = None,
                      tool_provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Classify observed intent; tool identity is only supporting evidence."""
    context = scenario_context or {}
    explicit = context.get("activity") or normalized_request.get("activity")
    if explicit:
        return {"activity": explicit, "classification": "confirmed", "evidence_markers": ["scenario_context"]}
    if normalized_request.get("body_parse_status") == "unclassified":
        return {"activity": None, "classification": "unclassified", "evidence_markers": []}
    markers = list(normalized_request.get("evidence_markers", ()))
    if len(markers) >= 2:
        return {"activity": "sql_injection_testing", "classification": "confirmed", "evidence_markers": markers}
    if markers:
        return {"activity": "sql_injection_testing", "classification": "partial", "evidence_markers": markers}
    values = [str(value) for value in (normalized_request.get("query") or {}).values()]
    if any(re.search(r"\b(?:select|union|and|or)\b", value, re.I) for value in values):
        return {"activity": "sql_injection_testing", "classification": "partial",
                "evidence_markers": ["sql_keyword_only"]}
    if tool_provenance and str(tool_provenance.get("tool", "")).casefold() in {"sqlmap", "burp"}:
        return {"activity": "sql_injection_testing", "classification": "partial", "evidence_markers": ["tool_provenance_only"]}
    method = str(normalized_request.get("method", "")).upper()
    if method == "GET":
        return {"activity": "authorized_data_read", "classification": "confirmed", "evidence_markers": ["read_operation"]}
    return {"activity": None, "classification": "unclassified", "evidence_markers": []}


def evaluate_activity_authorization(activity: Mapping[str, Any],
                                    policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Apply optional R3 policy to a classification; this function never blocks."""
    config = policy or {}
    allowed = tuple(config.get("allowed_activities", config.get("allowed", ())))
    prohibited = tuple(config.get("prohibited_activities", config.get("prohibited", ())))
    if not allowed and not prohibited:
        verdict = "not_applicable"
    elif activity.get("classification") != "confirmed" or not activity.get("activity"):
        verdict = "unclassified"
    elif activity["activity"] in prohibited:
        verdict = "violation"
    elif allowed and activity["activity"] not in allowed:
        verdict = "violation"
    else:
        verdict = "pass"
    return {
        "activity_authorization": verdict,
        "matched_policy_rule": (
            f"prohibited_activities.{activity.get('activity')}"
            if verdict == "violation" and activity.get("activity") in prohibited
            else f"allowed_activities.{activity.get('activity')}" if verdict == "pass" and allowed else None
        ),
    }