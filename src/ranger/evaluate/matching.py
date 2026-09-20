"""Shared declarative event-condition matching for evaluators."""

from typing import Any, Mapping

from ..core.event import Event


def nested_value(data: Mapping[str, Any], path: str) -> Any:
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def matches(event: Event, condition: Mapping[str, Any]) -> bool:
    """Return whether an event satisfies a declarative condition.

    Attribute comparison follows these explicit rules:

    | expected value | actual value | comparison |
    | list/tuple | list/tuple | every expected element is contained in actual |
    | list/tuple | scalar | actual is contained in expected |
    | mapping | mapping | every expected key/value is contained in actual |
    | otherwise | any | ordinary equality (``==``) |

    List containment is intentionally order-independent and allows the actual
    event to contain additional values, such as multiple response markers.
    """
    for field in ("actor", "source", "kind", "action"):
        if field in condition and getattr(event, field) != condition[field]:
            return False
    if "target" in condition and not target_matches(event.target, str(condition["target"])):
        return False
    for path, expected in condition.get("attributes", {}).items():
        actual = nested_value(event.attributes, path)
        if not _attribute_matches(actual, expected):
            return False
    return True


def _attribute_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping):
            return False
        return all(
            key in actual and _attribute_matches(actual[key], value)
            for key, value in expected.items()
        )
    expected_is_list = isinstance(expected, (list, tuple))
    actual_is_list = isinstance(actual, (list, tuple))
    if expected_is_list and actual_is_list:
        return all(item in actual for item in expected)
    if expected_is_list:
        return actual in expected
    return actual == expected


def target_matches(target: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    prefix = pattern.rstrip("/") or "/"
    return target == prefix or (prefix != "/" and (
        target.startswith(prefix + "/") or target.startswith(prefix + "?")
    ))


def evidence(index: int, event: Event) -> dict[str, Any]:
    return {
        "event_index": index,
        "seq": event.seq,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "kind": event.kind,
        "action": event.action,
        "target": event.target,
    }