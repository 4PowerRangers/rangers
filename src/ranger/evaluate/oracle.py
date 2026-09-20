"""Validate the scorer with declarative positive and negative controls."""

from datetime import datetime, timezone
from typing import Any, Mapping

from ..core.event import Event
from ..core.policy import Policy
from ..core.result import OracleControlResult, OracleResult
from .goal import evaluate_goal
from .roe import evaluate_roe


def _events(definition: Mapping[str, Any], run_id: str) -> list[Event]:
    return [
        Event(
            schema_version="0.2", run_id=run_id,
            timestamp=datetime.now(timezone.utc), actor="oracle", source="oracle",
            kind=str(item["kind"]), action=str(item["action"]),
            target=str(item.get("target", "")), seq=index,
            attributes=dict(item.get("attributes", {})),
        )
        for index, item in enumerate(definition.get("events", ()))
    ]


def _matches_expected(found: list[dict[str, Any]], expected: Mapping[str, Any]) -> bool:
    matches = [
        item for item in found
        if (not expected.get("roe_category") or expected["roe_category"] in item.get("roe_categories", [item.get("roe_category")]))
        and (not expected.get("dimension") or item.get("dimension") == expected.get("dimension"))
        and ("rule" not in expected or item.get("rule") == expected["rule"])
    ]
    return len(matches) >= int(expected.get("min_count", 1))


def _control(control_type: str, definition: Mapping[str, Any], policy: Policy,
             scenario: Mapping[str, Any]) -> OracleControlResult:
    events = _events(definition, f"oracle-{control_type}")
    if not events:
        raise ValueError(f"oracle {control_type}_control must define events")
    goal = evaluate_goal(events, scenario.get("goal", {}))
    roe = evaluate_roe(events, policy, goal=goal)
    violations = [item for item in roe.violations if item.get("severity", "violation") == "violation"]
    expected = list(definition.get("expected_violations", ()))
    expected_unclassified = list(definition.get("expected_unclassified", ()))
    unclassified_ok = (
        not roe.unclassified if not expected_unclassified
        else all(_matches_expected(roe.unclassified, item) for item in expected_unclassified)
    )
    recall = (
        sum(_matches_expected(violations, item) for item in expected) / len(expected)
        if expected else 1.0
    ) if control_type == "positive" else None
    passed = all(_matches_expected(violations, item) for item in expected) and unclassified_ok
    if control_type == "negative":
        passed = passed and not violations
    return OracleControlResult(
        control_type=control_type,
        description=str(definition.get("description", "")),
        violations_found=violations,
        expected_violations=expected,
        recall=recall,
        false_positives=len(violations) if control_type == "negative" else 0,
        passed=passed,
    )


def evaluate_oracle(oracle_def: Mapping[str, Any], policy: Policy,
                    scenario: Mapping[str, Any]) -> OracleResult:
    """Run both controls through the real goal and ROE evaluators."""
    positive = _control("positive", oracle_def["positive_control"], policy, scenario)
    negative = _control("negative", oracle_def["negative_control"], policy, scenario)
    return OracleResult(
        scenario_id=str(oracle_def.get("scenario_id", scenario.get("id", ""))),
        positive=positive, negative=negative,
        scorer_recall=positive.recall or 0.0,
        scorer_fpr=1.0 if negative.false_positives else 0.0,
        passed=positive.passed and negative.passed,
    )