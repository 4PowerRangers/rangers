"""Penetration-testing lifecycle progress evaluation over normalized events.

The evaluator judges lifecycle stage purely by replaying ``events.jsonl``
against declarative stage rules (event -> evidence -> stage). It never infers
stage from event counts, elapsed time, or the agent's own self-reported
``done``/``thought`` text.

Lifecycle (target model, extensible):
    S1  Recon / Initial Access
    S2  Internal Expansion / Goal
    S3  Detection / Response Validation
    S4  Cleanup / Withdrawal
    S5  Reporting

Only S1 and S2 have concrete, Juice-Shop-verifiable rules today. S3-S5 are
represented by the same ``StageRule`` interface so an environment or scenario
can supply rules for them later without touching this module.

Stage rules are NOT hardcoded here for any specific target. A scenario or
environment adapter supplies a list of ``StageRule`` (or the equivalent
plain-dict form loaded from scenario/environment config) via
``evaluate_progress(events, stage_rules=...)``. If no rules are supplied,
this module falls back to the scenario's own ``goal.progress`` config so
existing scenario.yaml files keep working, but that fallback carries no
built-in path knowledge either -- it is just declarative matching, same as
before.
"""

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..core.event import Event
from ..core.result import ProgressResult
from .matching import evidence, matches


LIFECYCLE_STAGES: dict[int, str] = {
    1: "Recon / Initial Access",
    2: "Internal Expansion / Goal",
    3: "Detection / Response Validation",
    4: "Cleanup / Withdrawal",
    5: "Reporting",
}


@dataclass(frozen=True)
class StageRule:
    """One lifecycle stage's declarative match condition(s).

    ``stage`` is the lifecycle stage number (1-5). ``name`` is a short
    identifier for this rule (distinct rules may share a stage number, e.g.
    several ways to reach S2). ``when`` follows the same event-condition
    shape used elsewhere in evaluate/matching.py: optional ``kind``,
    ``action``, ``actor``, ``source``, ``target`` (prefix-matched), and
    ``attributes`` (dotted-path equality).
    """

    stage: int
    name: str
    when: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StageRule":
        return cls(
            stage=int(data["stage"]),
            name=str(data.get("name", f"stage_{data['stage']}")),
            when=dict(data.get("when", {})),
        )


def default_stage_rules_from_goal(goal: Mapping[str, Any]) -> list[StageRule]:
    """Back-compat bridge: build StageRules from a scenario's goal.progress.

    This keeps existing scenario.yaml ``goal.progress`` blocks working
    without this module hardcoding any environment-specific path. The
    scenario file itself is the injected config in that case.
    """
    return [StageRule.from_dict(rule) for rule in goal.get("progress", [])]


def evaluate_progress(
    events: Sequence[Event],
    goal: Mapping[str, Any] | None = None,
    *,
    stage_rules: Sequence[StageRule] | Sequence[Mapping[str, Any]] | None = None,
) -> ProgressResult:
    """Replay events against lifecycle stage rules in event order.

    For each event (in order), each stage rule is checked; a rule that
    matches records evidence for its stage. The current/highest stage is the
    greatest stage number with at least one matching event; every stage with
    at least one match is "completed" (reachable stages are monotonic in
    practice because rules are checked in event order, but no ordering
    constraint between stages is enforced here -- that is a rule-design
    concern, not this evaluator's).
    """
    rules = _resolve_rules(stage_rules, goal)
    evidence_by_stage_name: dict[str, list[dict[str, Any]]] = {rule.name: [] for rule in rules}

    for index, event in enumerate(events):
        for rule in rules:
            if matches(event, rule.when):
                evidence_by_stage_name[rule.name].append(evidence(index, event))

    completed_names = [rule.name for rule in rules if evidence_by_stage_name[rule.name]]
    reached_stage_numbers = {rule.stage for rule in rules if evidence_by_stage_name[rule.name]}
    current_stage = max(reached_stage_numbers, default=0)
    current_stage_name = (
        LIFECYCLE_STAGES.get(current_stage) if current_stage else None
    )

    return ProgressResult(
        current_stage=current_stage,
        stage_name=current_stage_name,
        completed_stages=completed_names,
        evidence=evidence_by_stage_name,
    )


def _resolve_rules(
    stage_rules: Sequence[StageRule] | Sequence[Mapping[str, Any]] | None,
    goal: Mapping[str, Any] | None,
) -> list[StageRule]:
    if stage_rules is not None:
        return [
            rule if isinstance(rule, StageRule) else StageRule.from_dict(rule)
            for rule in stage_rules
        ]
    return default_stage_rules_from_goal(goal or {})