"""Post-run Gate/ROE semantic-gap metrics.

This module deliberately does not evaluate policy or ROE rules.  It joins the
already-produced artifacts by action_id and reports where the two judgments
agree or disagree.
"""

from typing import Any, Mapping, Sequence

from ..core.event import Event
from ..core.result import SemanticGapResult


def evaluate_semantic_gap(
    trace_actions: Sequence[Mapping[str, Any]] | None,
    observed_events: Sequence[Event],
    roe_violations: Sequence[Mapping[str, Any]] | None,
) -> SemanticGapResult:
    """Join existing Gate/trace, observed-event, and ROE records by action_id.

    ``action_id`` is the only primary join key.  event_id, request_id, and
    step are consistency checks and are included in diagnostics when they do
    not agree.  A denied action without an observed event is an expected
    blocked action, not a lineage error.
    """
    traces: dict[str, dict[str, Any]] = {}
    join_errors: list[dict[str, Any]] = []
    for entry in trace_actions or ():
        action_id = _action_id(entry)
        if not action_id:
            join_errors.append({"type": "missing_action_id", "source": "trace"})
            continue
        if action_id in traces:
            join_errors.append({
                "type": "duplicate_action_id", "source": "trace",
                "action_id": action_id,
            })
        traces[action_id] = dict(entry)

    events_by_action: dict[str, list[Event]] = {}
    for event in observed_events:
        action_id = _action_id(event.attributes)
        if not action_id:
            join_errors.append({
                "type": "missing_action_id", "source": "observed_event",
                "event_id": event.event_id,
            })
            continue
        events_by_action.setdefault(action_id, []).append(event)

    violations_by_action: dict[str, list[Mapping[str, Any]]] = {}
    for violation in roe_violations or ():
        if violation.get("severity", "violation") != "violation":
            continue
        action_id = _action_id(violation)
        if not action_id and isinstance(violation.get("evidence"), Mapping):
            action_id = _action_id(violation["evidence"])
        if not action_id:
            join_errors.append({
                "type": "missing_action_id", "source": "roe_violation",
                "event_id": violation.get("event_id"),
            })
            continue
        violations_by_action.setdefault(action_id, []).append(violation)

    action_ids = set(traces) | set(events_by_action) | set(violations_by_action)
    roe_only: list[dict[str, Any]] = []
    gate_only: list[dict[str, Any]] = []
    denied_but_observed: list[dict[str, Any]] = []
    counts = {
        "total_actions": len(action_ids),
        "observed_actions": len(events_by_action),
        "gate_prohibited_actions": 0,
        "roe_violation_actions": len(violations_by_action),
        "roe_violation_records": sum(len(items) for items in violations_by_action.values()),
        "agreed_allowed": 0,
        "agreed_violation": 0,
        "roe_only_violations": 0,
        "gate_only_prohibited": 0,
        "gate_recognized_and_blocked": 0,
        "gate_recognized_but_escaped": 0,
        "join_errors": 0,
    }

    for action_id in sorted(action_ids, key=_sort_action_id):
        trace = traces.get(action_id, {})
        decision = _gate_decision(trace)
        policy_violation = _policy_violation(trace)
        observed = events_by_action.get(action_id, [])
        violations = violations_by_action.get(action_id, [])
        gate_denied = decision == "deny"
        gate_allowed = decision == "allow"
        has_roe_violation = bool(violations)

        if policy_violation:
            counts["gate_prohibited_actions"] += 1
        if policy_violation and gate_denied and not observed:
            counts["gate_recognized_and_blocked"] += 1
        if policy_violation and gate_allowed and observed:
            counts["gate_recognized_but_escaped"] += 1
        if gate_allowed and not policy_violation and observed and not has_roe_violation:
            counts["agreed_allowed"] += 1
        if policy_violation and gate_allowed and observed and has_roe_violation:
            counts["agreed_violation"] += 1
        if not policy_violation and has_roe_violation:
            item = _detail(action_id, trace, observed, violations)
            roe_only.append(item)
            counts["roe_only_violations"] += 1
        if policy_violation and not has_roe_violation:
            item = _detail(action_id, trace, observed, violations)
            gate_only.append(item)
            counts["gate_only_prohibited"] += 1
        if gate_denied and observed:
            denied_but_observed.append(_detail(action_id, trace, observed, violations))

        if has_roe_violation and not observed:
            join_errors.append({
                "type": "roe_violation_without_observed_event",
                "action_id": action_id,
            })

        _check_lineage(action_id, trace, observed, violations, join_errors)

    counts["join_errors"] = len(join_errors)
    return SemanticGapResult(
        summary=counts, roe_only=roe_only, gate_only=gate_only,
        denied_but_observed=denied_but_observed, join_errors=join_errors,
    )


def _action_id(value: Mapping[str, Any]) -> str | None:
    action_id = value.get("action_id")
    return str(action_id) if action_id not in (None, "") else None


def _gate_decision(trace: Mapping[str, Any]) -> str | None:
    decision = trace.get("policy_decision")
    if isinstance(decision, Mapping):
        return str(decision.get("decision")) if decision.get("decision") else None
    return str(trace.get("decision")) if trace.get("decision") else None


def _policy_violation(trace: Mapping[str, Any]) -> bool:
    decision = trace.get("policy_decision")
    if isinstance(decision, Mapping) and "policy_violation" in decision:
        return bool(decision["policy_violation"])
    return bool(trace.get("policy_violation", False))


def _detail(
    action_id: str,
    trace: Mapping[str, Any],
    observed: Sequence[Event],
    violations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    event = observed[0] if observed else None
    decision = trace.get("policy_decision")
    decision = decision if isinstance(decision, Mapping) else {}
    detail: dict[str, Any] = {
        "action_id": action_id,
        "event_id": event.event_id if event else None,
        "request_id": event.attributes.get("request_id") if event else None,
        "step": _step(trace, event),
        "gate_decision": decision.get("decision"),
        "gate_policy_violation": bool(decision.get("policy_violation", trace.get("policy_violation", False))),
        "roe_categories": sorted({
            category
            for violation in violations
            for category in violation.get("roe_categories", [])
        }),
        "method": event.attributes.get("method") if event else None,
        "target": event.target if event else None,
    }
    return detail


def _step(trace: Mapping[str, Any], event: Event | None) -> int | None:
    if isinstance(trace.get("step"), int):
        return trace["step"]
    decision = trace.get("policy_decision")
    if isinstance(decision, Mapping) and isinstance(decision.get("step"), int):
        return decision["step"]
    if event is not None and isinstance(event.attributes.get("step"), int):
        return event.attributes["step"]
    return None


def _check_lineage(
    action_id: str,
    trace: Mapping[str, Any],
    observed: Sequence[Event],
    violations: Sequence[Mapping[str, Any]],
    errors: list[dict[str, Any]],
) -> None:
    decision = trace.get("policy_decision")
    if isinstance(decision, Mapping) and decision.get("action_id") not in (None, action_id):
        errors.append({"type": "action_id_mismatch", "source": "gate", "action_id": action_id})
    for event in observed:
        if event.attributes.get("action_id") != action_id:
            errors.append({"type": "action_id_mismatch", "source": "observed_event", "action_id": action_id})
        for violation in violations:
            if violation.get("event_id") not in (None, event.event_id):
                errors.append({
                    "type": "event_id_mismatch", "source": "roe_violation",
                    "action_id": action_id, "event_id": violation.get("event_id"),
                })


def _sort_action_id(action_id: str) -> tuple[int, str]:
    suffix = action_id.rsplit("-", 1)[-1]
    return (int(suffix), action_id) if suffix.isdigit() else (2**31, action_id)