from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if any(word in str(k).lower() for word in
                ("token", "secret", "password", "authorization", "api_key")) else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


@dataclass
class ToolInvocation:
    run_id: str
    action_id: str
    tool_name: str
    arguments: Any
    runtime: str = "container"
    container: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    status: str = "created"
    exit_code: int | None = None
    child_event_count: int = 0
    process: dict[str, Any] | None = None
    seq: int | None = None
    request_id: str | None = None
    proposed_activity: str | None = None
    canonical_activity: str | None = None
    canonical_intent: str | None = None
    canonical_operation: str | None = None
    activity_normalization_status: str | None = None
    _started: float | None = field(default=None, repr=False)

    def record(self, stage: str, **extra: Any) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        if stage == "execution_started":
            self.status, self.started_at, self._started = "running", now, datetime.now().timestamp()
        elif stage == "execution_finished":
            self.status, self.finished_at = extra.pop("status", "completed"), now
            self.child_event_count = extra.get("child_event_count", self.child_event_count)
        return {"event_type": "tool_invocation", "stage": stage, "run_id": self.run_id,
                "action_id": self.action_id, "tool_name": self.tool_name,
                "arguments": redact(self.arguments), "runtime": self.runtime,
                "container": self.container, "status": self.status,
                "child_event_count": self.child_event_count, "process": self.process,
                "seq": self.seq, "proposed_activity": self.proposed_activity,
                "request_id": self.request_id,
                "canonical_activity": self.canonical_activity,
                "canonical_intent": self.canonical_intent,
                "canonical_operation": self.canonical_operation,
                "activity_normalization_status": self.activity_normalization_status, **extra}

    def bind_process(self, process: Mapping[str, Any]) -> None:
        self.process = redact(dict(process))

    def bind_activity(self, normalized_action: Mapping[str, Any], *,
                      proposed_activity: Any = None) -> None:
        self.proposed_activity = proposed_activity
        self.canonical_activity = normalized_action.get("activity")
        self.canonical_intent = normalized_action.get("intent")
        self.canonical_operation = normalized_action.get("operation")
        self.activity_normalization_status = normalized_action.get("normalization_status")


def child_correlation(action_id: str | None, *, token_valid: bool,
                      candidate_count: int = 1) -> dict[str, Any]:
    if not action_id or not token_valid:
        return {"parent_action_id": None, "correlation_status": "orphan"}
    if candidate_count != 1:
        return {"parent_action_id": None, "correlation_status": "ambiguous"}
    return {"parent_action_id": action_id, "correlation_status": "correlated"}