from dataclasses import asdict, dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .policy import Policy


@dataclass(frozen=True)
class PolicySubject:

    action_id: str | None
    kind: str
    method: str | None = None
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    operation: str | None = None
    resource: str | None = None
    behavior: str | None = None
    target: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyFinding:
    rule_id: str
    dimension: str
    category: str | None
    prohibited: bool
    subject: str | None
    target: str | None
    resource: str | None
    operation: str | None
    host: str | None
    port: int | None
    scheme: str | None
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def subject_from_action(action: Mapping[str, Any], *, action_id: str | None = None) -> PolicySubject:
    target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
    scheme = action.get("protocol") or action.get("scheme")
    host = target.get("host") or action.get("host")
    port = _int_or_none(target.get("port") or action.get("port"))
    path = action.get("resource") or action.get("path")
    target_url = action.get("url") or action.get("target_url")
    if not isinstance(target_url, str) and scheme and host:
        target_url = _url(scheme, host, port, path)
    return PolicySubject(
        action_id=action_id or action.get("action_id"),
        kind="proposed_action",
        method=str(action["method"]).upper() if action.get("method") else None,
        scheme=str(scheme) if scheme else None,
        host=str(host) if host else None,
        port=port,
        path=str(path) if path else None,
        operation=_lower(action.get("operation")),
        resource=str(action.get("resource")) if action.get("resource") else None,
        behavior=(action.get("activity") or action.get("behavior")),
        target=str(target_url) if target_url else None,
        attributes={
            **dict(action),
            "action": action.get("action") or (
                "request" if action.get("action_channel") == "native_http" else None
            ),
        },
    )


def subject_from_event(event: Any) -> PolicySubject:
    attributes = dict(getattr(event, "attributes", {}) or {})
    parsed = urlsplit(str(getattr(event, "target", "")))
    scheme = attributes.get("scheme") or parsed.scheme or None
    host = attributes.get("host") or parsed.hostname or None
    port = _int_or_none(attributes.get("port") or parsed.port)
    if port is None and scheme:
        port = 443 if str(scheme).lower() == "https" else 80
    path = attributes.get("path") or parsed.path or None
    return PolicySubject(
        action_id=attributes.get("action_id"),
        kind=str(getattr(event, "kind", "observed_event")),
        method=(str(attributes["method"]).upper() if attributes.get("method") else None),
        scheme=str(scheme) if scheme else None,
        host=str(host) if host else None,
        port=port,
        path=str(path) if path else None,
        operation=_lower(attributes.get("operation")),
        resource=(str(attributes["resource"]) if attributes.get("resource") else None),
        behavior=attributes.get("activity") or attributes.get("behavior"),
        target=str(getattr(event, "target", "")) or None,
        attributes=attributes,
    )


def evaluate_policy_subject(
    subject: PolicySubject,
    policy: Policy,
    *,
    include_roe_categories: bool = True,
) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    allowed = policy.allowed
    forbidden = policy.forbidden
    for dimension, value, allowed_values, forbidden_values, matcher, category in (
        ("target", subject.target, allowed.targets, forbidden.targets, _target_matches, "R1"),
        ("action", subject.attributes.get("action"), allowed.actions, forbidden.actions, _equal, None),
        ("resource", subject.resource, allowed.resources, forbidden.resources, _equal, "R1"),
        ("behavior", subject.behavior, allowed.behaviors, forbidden.behaviors, _equal, "R3"),
        ("host", subject.host, policy.scope.allowed_hosts, policy.scope.forbidden_hosts, _equal, "R1"),
        ("port", subject.port, policy.scope.allowed_ports, policy.scope.forbidden_ports, _port_matches, "R1"),
        ("scheme", subject.scheme, policy.scope.allowed_schemes, policy.scope.forbidden_schemes, _equal, "R1"),
    ):
        if value is None:
            continue
        if dimension == "target" and _target_namespace_mismatch(
            value, (*allowed_values, *forbidden_values),
        ):
            continue
        if dimension == "resource" and _resource_namespace_mismatch(
            value, (*allowed_values, *forbidden_values),
        ):
            continue
        forbidden_rule = next((rule for rule in forbidden_values if matcher(value, rule)), None)
        if forbidden_rule is not None:
            findings.append(_finding(
                subject, dimension, category, True, "forbidden",
                f"policy.forbidden.{dimension}", forbidden_rule,
            ))
            continue
        if allowed_values and not any(matcher(value, rule) for rule in allowed_values):
            findings.append(_finding(
                subject, dimension, category, True, "not_allowed",
                f"policy.allowed.{dimension}", None,
            ))

    if include_roe_categories:
        _category_findings(findings, subject, policy, "target_authorization", "target", "R1")
        _category_findings(findings, subject, policy, "technical_operations", "operation", "R4")
        _category_findings(findings, subject, policy, "activity_authorization", "behavior", "R3")
    return findings


def _category_findings(
    findings: list[PolicyFinding], subject: PolicySubject, policy: Policy,
    config_name: str, dimension: str, category: str,
) -> None:
    config = policy.roe.get(config_name) or {}
    value = subject.operation if dimension == "operation" else subject.behavior
    if not config or value is None:
        return
    allowed = tuple(config.get("allowed", config.get("allowed_activities", ())))
    prohibited = tuple(config.get(
        "prohibited", config.get("prohibited_activities", config.get("excluded", ()))
    ))
    if dimension == "target" and _target_namespace_mismatch(
        value, (*allowed, *prohibited),
    ):
        return
    prohibited_rule = next((rule for rule in prohibited if _equal(value, rule)), None)
    if prohibited_rule is not None:
        findings.append(_finding(
            subject, dimension, category, True, "forbidden",
            f"policy.roe.{config_name}.prohibited", prohibited_rule,
        ))
    elif allowed and not any(_equal(value, rule) for rule in allowed):
        findings.append(_finding(
            subject, dimension, category, True, "not_allowed",
            f"policy.roe.{config_name}.allowed", None,
        ))


def _finding(subject: PolicySubject, dimension: str, category: str | None,
             prohibited: bool, reason: str, rule_id: str,
             matched_rule: Any) -> PolicyFinding:
    return PolicyFinding(
        rule_id=rule_id, dimension=dimension, category=category,
        prohibited=prohibited, subject=_subject_value(subject, dimension),
        target=subject.target, resource=subject.resource,
        operation=subject.operation, host=subject.host, port=subject.port,
        scheme=subject.scheme, reason=reason,
        metadata={"matched_rule": matched_rule, "action_id": subject.action_id},
    )


def _subject_value(subject: PolicySubject, dimension: str) -> str | None:
    value = subject.target if dimension == "target" else getattr(subject, dimension, None)
    return str(value) if value is not None else None


def _target_matches(actual: Any, expected: Any) -> bool:
    if not isinstance(actual, str) or not isinstance(expected, str):
        return actual == expected
    actual_parts = urlsplit(actual)
    expected_parts = urlsplit(expected)
    if actual_parts.scheme and expected_parts.scheme:
        if (actual_parts.scheme.lower(), (actual_parts.hostname or "").lower(),
                _effective_port(actual_parts),) != (
                expected_parts.scheme.lower(), (expected_parts.hostname or "").lower(),
                _effective_port(expected_parts),
        ):
            return False
        actual_path = actual_parts.path or "/"
        expected_path = expected_parts.path or "/"
        return actual_path == expected_path or (
            expected_path != "/" and actual_path.startswith(expected_path.rstrip("/") + "/")
        )
    if expected == "*":
        return True
    return actual == expected or (expected.rstrip("/") != "/" and actual.startswith(expected.rstrip("/") + "/"))


def _target_namespace_mismatch(value: Any, declared: tuple[Any, ...]) -> bool:
    if not isinstance(value, str):
        return False
    observed_scheme = urlsplit(value).scheme.casefold()
    declared_schemes = {
        urlsplit(item).scheme.casefold()
        for item in declared if isinstance(item, str) and "://" in item
    }
    return bool(observed_scheme and declared_schemes and observed_scheme not in declared_schemes)


def _resource_namespace_mismatch(value: Any, declared: tuple[Any, ...]) -> bool:
    if not isinstance(value, str):
        return False
    declared_strings = [item for item in declared if isinstance(item, str)]
    return value.startswith("/") and bool(declared_strings) and all(
        not item.startswith("/") for item in declared_strings
    )


def _equal(actual: Any, expected: Any) -> bool:
    return str(actual).casefold() == str(expected).casefold()


def _port_matches(actual: Any, expected: Any) -> bool:
    try:
        return int(actual) == int(expected)
    except (TypeError, ValueError):
        return False


def _effective_port(value: Any) -> int | None:
    port = value.port
    if port is not None:
        return port
    return 443 if value.scheme.lower() == "https" else 80


def _url(scheme: Any, host: Any, port: int | None, path: Any) -> str:
    default = (str(scheme).lower() == "https" and port == 443) or (
        str(scheme).lower() == "http" and port == 80
    )
    netloc = str(host) if default or port is None else f"{host}:{port}"
    return urlunsplit((str(scheme).lower(), netloc, str(path or "/"), "", ""))


def _lower(value: Any) -> str | None:
    return str(value).lower() if value is not None else None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None