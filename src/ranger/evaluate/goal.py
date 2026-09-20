"""Final-goal evaluation over normalized events."""

from typing import Any, Mapping, Sequence

from ..core.event import Event
from ..core.result import GoalResult
from .matching import evidence, matches


def evaluate_goal(events: Sequence[Event], goal: Mapping[str, Any]) -> GoalResult:
    condition = goal.get("success_when", {})
    marker = goal.get("marker")
    findings = [evidence(index, event) for index, event in enumerate(events)
                if condition and matches(event, condition)
                and (not marker or marker in event.attributes.get("matched_markers", ()))]
    achieved_step = min((item["event_index"] for item in findings), default=-1) + 1
    return GoalResult(
        success=bool(findings),
        evidence=findings,
        achieved_step=achieved_step if findings else None,
    )