import json
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Collection, Mapping
from urllib.parse import urlsplit, urlunsplit

from ..core.event import Event
from ..core.lifecycle import validate_lifecycle
from ..core.policy import Policy
from ..core.result import (
    RealSystemActivity, DatabaseImpact, GoalResult, Metrics, ObserverHealth,
    ProgressResult, RoeResult, Validity,
)
from ..core.run import RunConfig
from .goal import evaluate_goal
from .progress import evaluate_progress
from .roe import evaluate_roe
from .declare import evaluate_declarations
from .semantic_gap import evaluate_semantic_gap


@dataclass(frozen=True)
class RoeSnapshot:
    """ROE/goal state computed from the events observed so far."""

    events: list[Event]
    environment_events: list[Event]
    goal: GoalResult
    goal_achieved_seq: int | None
    roe: RoeResult


def load_events(events_path: Path) -> list[Event]:
    with Path(events_path).open(encoding="utf-8") as stream:
        return [_upgrade_legacy_semantics(Event.from_dict(json.loads(line)))
                for line in stream if line.strip()]


def _upgrade_legacy_semantics(event: Event) -> Event:
    """Backfill v2 channel/operation facts for pre-separation artifacts."""
    attributes = dict(event.attributes)
    if "action_channel" in attributes:
        return event
    canonical_action = attributes.get("canonical_action")
    canonical_tool = (
        canonical_action.get("tool")
        if isinstance(canonical_action, Mapping)
        and isinstance(canonical_action.get("tool"), Mapping)
        else {}
    )
    tool_name = attributes.get("tool_name") or canonical_tool.get("name")
    if str(tool_name).casefold() == "http_request":
        attributes["action_channel"] = "native_http"
        attributes["tool_name"] = None
        attributes["tool_type"] = None
        attributes["operation"] = {
            "GET": "read", "HEAD": "inspect", "OPTIONS": "capability_discovery",
            "POST": "create", "PUT": "modify", "PATCH": "modify",
            "DELETE": "delete",
        }.get(str(attributes.get("method", "")).upper(), attributes.get("operation"))
    elif tool_name is not None or canonical_tool:
        attributes["action_channel"] = "command"
    else:
        return event
    return replace(event, attributes=attributes)


def load_trace(trace_path: Path) -> list[dict[str, Any]]:
    with Path(trace_path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def load_invocations(invocations_path: Path) -> list[dict[str, Any]]:
    with Path(invocations_path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def load_lifecycle(lifecycle_path: Path, *, run_id: str) -> tuple[bool, str | None]:
    """Validate lifecycle JSONL, converting parse/validation errors to reasons."""
    try:
        with Path(lifecycle_path).open(encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        validate_lifecycle(records, expected_run_id=run_id)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        return False, f"lifecycle_invalid:{type(error).__name__}:{error}"
    return True, None


def normalize_targets(events: list[Event], environment: Mapping[str, Any] | None) -> list[Event]:
    """Map environment runtime endpoints to their stable target identity."""
    target = (environment or {}).get("target", {})
    identity = target.get("base_url")
    aliases = target.get("runtime_aliases", ())
    if not identity or not aliases:
        return events

    identity_url = urlsplit(identity)
    normalized = []
    for event in events:
        event_url = urlsplit(event.target)
        alias_url = next(
            (urlsplit(alias) for alias in aliases
             if _same_endpoint(event_url, urlsplit(alias))),
            None,
        )
        if alias_url is None:
            normalized.append(event)
            continue
        attributes = dict(event.attributes)
        attributes["runtime"] = {
            key: attributes[key] for key in ("scheme", "host", "port") if key in attributes
        }
        attributes.update({
            "scheme": identity_url.scheme,
            "host": identity_url.hostname,
            "port": identity_url.port or (443 if identity_url.scheme == "https" else 80),
        })
        normalized.append(replace(
            event,
            target=urlunsplit((identity_url.scheme, identity_url.netloc,
                               event_url.path, event_url.query, event_url.fragment)),
            attributes=attributes,
        ))
    return normalized


def evaluate_roe_snapshot(
    events: list[Event], scenario: Mapping[str, Any], policy: Policy,
    config: RunConfig, *, environment: Mapping[str, Any] | None = None,
    invocations: list[dict[str, Any]] | None = None,
) -> RoeSnapshot:
    """Evaluate the observed prefix with the same semantics as final evaluation."""
    normalized = normalize_targets(list(events), environment)
    if normalized and all(event.seq >= 0 for event in normalized):
        normalized.sort(key=lambda event: event.seq)
    elif any(event.seq >= 0 for event in normalized):
        raise ValueError("mixed legacy and sequenced events")

    environment_events = [event for event in normalized if event.kind != "database"]
    goal = evaluate_goal(environment_events, scenario.get("goal", {}))
    goal_achieved_seq = None
    if goal.achieved_step is not None:
        goal_event = environment_events[goal.achieved_step - 1]
        goal_achieved_seq = goal_event.seq if goal_event.seq >= 0 else None
    roe = evaluate_roe(
        environment_events, policy, goal=goal,
        database_events=[event for event in normalized if event.kind == "database"],
        bookkeeping_tables=(environment or {}).get("database", {}).get(
            "bookkeeping_tables", ()
        ),
        goal_achieved_seq=goal_achieved_seq,
        invocations=invocations or [],
        source_semantics_version=config.roe_semantics_version,
    )
    return RoeSnapshot(normalized, environment_events, goal, goal_achieved_seq, roe)


def _same_endpoint(left: Any, right: Any) -> bool:
    def endpoint(url: Any) -> tuple[str, str | None, int]:
        return (url.scheme, url.hostname,
                url.port or (443 if url.scheme == "https" else 80))
    return endpoint(left) == endpoint(right)


def summarize_database_impact(events: list[Event], goal_achieved_seq: int | None = None,
                              bookkeeping_tables: Collection[str] = (),
                              legacy_goal_at: datetime | None = None
                              ) -> DatabaseImpact:
    database_events = [event for event in events if event.kind == "database"]
    writes = [
        (event, {
            key: event.attributes[key]
            for key in ("operation", "table", "behavior", "affected_rows")
            if key in event.attributes
        })
        for event in database_events
        if event.attributes.get("behavior") != "read"
    ]
    modifications = [modification for _, modification in writes]
    pre_goal = [
        modification for event, modification in writes
        if (event.timestamp <= legacy_goal_at if legacy_goal_at is not None
            else goal_achieved_seq is None or event.seq <= goal_achieved_seq)
    ]
    post_goal = [
        modification for event, modification in writes
        if ((event.timestamp > legacy_goal_at if legacy_goal_at is not None
             else goal_achieved_seq is not None and event.seq > goal_achieved_seq))
    ]
    bookkeeping = {table.casefold() for table in bookkeeping_tables}
    business = [
        (event, modification) for event, modification in writes
        if str(modification.get("table", "")).casefold() not in bookkeeping
    ]
    pre_goal_business = [
        modification for event, modification in business
        if (event.timestamp <= legacy_goal_at if legacy_goal_at is not None
            else goal_achieved_seq is None or event.seq <= goal_achieved_seq)
    ]
    post_goal_business = [
        modification for event, modification in business
        if ((event.timestamp > legacy_goal_at if legacy_goal_at is not None
             else goal_achieved_seq is not None and event.seq > goal_achieved_seq))
    ]
    return DatabaseImpact(
        queries=len(database_events),
        writes=len(modifications),
        modifications=modifications,
        pre_goal_writes=len(pre_goal),
        post_goal_writes=len(post_goal),
        pre_goal_modifications=pre_goal,
        post_goal_modifications=post_goal,
        business_writes=len(business),
        pre_goal_business_writes=len(pre_goal_business),
        post_goal_business_writes=len(post_goal_business),
        business_modifications=[modification for _, modification in business],
    )


def evaluate_run(events_path: Path, scenario: Mapping[str, Any], policy: Policy,
                 config: RunConfig, *, environment: Mapping[str, Any] | None = None,
                 observers: ObserverHealth | None = None,
                 lifecycle_path: Path | None = None
                 ) -> RealSystemActivity:
    observers = observers or ObserverHealth()
    observer_failure = next(
        (name for name in ("gateway", "database")
         if getattr(observers, name) != "ok"),
        None,
    )
    invalidity = (
        Validity(False, f"observer_failed:{observer_failure}")
        if observer_failure else None
    )
    if lifecycle_path is not None:
        lifecycle_valid, lifecycle_reason = load_lifecycle(lifecycle_path, run_id=config.run_id)
        if not lifecycle_valid and invalidity is None:
            invalidity = Validity(False, lifecycle_reason)
    events = load_events(events_path)
    trace_path = Path(events_path).with_name("trace.jsonl")
    trace_entries = load_trace(trace_path) if trace_path.is_file() else None
    invocations_path = Path(events_path).with_name("invocations.jsonl")
    invocations = load_invocations(invocations_path) if invocations_path.is_file() else []
    if any(event.seq >= 0 for event in events) and any(event.seq < 0 for event in events):
        raise ValueError("mixed legacy and sequenced events")
    if events and all(event.seq >= 0 for event in events):
        events.sort(key=lambda event: event.seq)
    foreign_run_ids = sorted({event.run_id for event in events if event.run_id != config.run_id})
    if foreign_run_ids:
        raise ValueError(
            f"events.jsonl contains events outside run {config.run_id!r}: {foreign_run_ids}"
        )
    declarations = (
        evaluate_declarations(trace_entries, events) if trace_entries is not None else None
    )
    if not events:
        return RealSystemActivity(
            run_id=config.run_id,
            goal=GoalResult(False),
            progress=ProgressResult(0),
            roe=RoeResult(False),
            metrics=Metrics(0, 0.0),
            status="invalid",
            observers=observers,
            validity=invalidity or Validity(False, "no_observed_events"),
            declarations=declarations,
            semantic_gap=evaluate_semantic_gap(trace_entries or [], [], []),
        )
    elapsed = max(
        0.0,
        max((event.timestamp for event in events), default=config.started_at).timestamp()
        - config.started_at.timestamp(),
    )
    environment_rules = (environment or {}).get("lifecycle", {}).get("progress") or []
    scenario_rules = scenario.get("goal", {}).get("progress") or []
    merged_rules = environment_rules + scenario_rules
    snapshot = evaluate_roe_snapshot(
        events, scenario, policy, config, environment=environment,
        invocations=invocations,
    )
    events = snapshot.events
    environment_events = snapshot.environment_events
    goal_result = snapshot.goal
    goal_achieved_seq = snapshot.goal_achieved_seq
    bookkeeping_tables = (environment or {}).get("database", {}).get(
        "bookkeeping_tables", ()
    )
    legacy_goal_at = None
    if goal_achieved_seq is None and goal_result.evidence and all(event.seq < 0 for event in events):
        legacy_goal_at = datetime.fromisoformat(goal_result.evidence[0]["timestamp"])
    db_impact = summarize_database_impact(
        events, goal_achieved_seq, legacy_goal_at=legacy_goal_at,
        bookkeeping_tables=bookkeeping_tables,
    )
    result = RealSystemActivity(
        run_id=config.run_id,
        goal=goal_result,
        progress=evaluate_progress(
            environment_events, scenario.get("goal", {}),
            stage_rules=merged_rules if merged_rules else None,
        ),
        roe=snapshot.roe,
        metrics=Metrics(steps=len(environment_events), duration_sec=round(elapsed, 3)),
        db_impact=db_impact if db_impact.queries else None,
        observers=observers,
        declarations=declarations,
        semantic_gap=evaluate_semantic_gap(
            trace_entries or [], events, snapshot.roe.violations,
        ),
    )
    return replace(result, status="invalid", validity=invalidity) if invalidity else result