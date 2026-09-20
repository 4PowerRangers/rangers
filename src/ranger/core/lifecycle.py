from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

LIFECYCLE_STAGES = ("proposed", "policy_decision", "executed", "observed")


@dataclass(frozen=True)
class LifecycleEvent:
    run_id: str
    seq: int
    timestamp: datetime
    action_id: str
    parent_action_id: str | None
    actor: str
    source: str
    stage: str
    raw_action: Any | None = None
    reference: Any | None = None
    normalized_action: Any | None = None
    decision: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.stage not in LIFECYCLE_STAGES:
            raise ValueError(f"unsupported lifecycle stage: {self.stage}")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        if self.seq < 0 or not self.run_id or not self.action_id:
            raise ValueError("run_id, action_id, and non-negative seq are required")
        if self.raw_action is None and self.reference is None:
            raise ValueError("raw_action or reference is required")

    def to_dict(self) -> dict[str, Any]:
        data = {
            "type": self.stage, "run_id": self.run_id, "seq": self.seq,
            "timestamp": self.timestamp.isoformat(), "action_id": self.action_id,
            "parent_action_id": self.parent_action_id, "actor": self.actor,
            "source": self.source, "stage": self.stage,
            "raw_action": self.raw_action, "reference": self.reference,
            "normalized_action": self.normalized_action,
        }
        if self.decision is not None:
            data["decision"] = self.decision
        if self.reason is not None:
            data["reason"] = self.reason
        return data

    @classmethod
    def now(cls, *, run_id: str, seq: int, action_id: str, actor: str,
            source: str, stage: str, raw_action: Any | None = None,
            reference: Any | None = None, normalized_action: Any | None = None,
            decision: str | None = None, reason: str | None = None) -> "LifecycleEvent":
        return cls(
            run_id=run_id, seq=seq, timestamp=datetime.now(timezone.utc),
            action_id=action_id, parent_action_id=None, actor=actor,
            source=source, stage=stage, raw_action=raw_action,
            reference=reference, normalized_action=normalized_action,
            decision=decision, reason=reason,
        )


def validate_lifecycle(records: list[Mapping[str, Any]], *, expected_run_id: str | None = None) -> None:
    order = {stage: index for index, stage in enumerate(LIFECYCLE_STAGES)}
    grouped: dict[str, list[str]] = {}
    correlations: dict[str, tuple[Any, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping) or not record.get("action_id") or not record.get("stage"):
            raise ValueError("malformed lifecycle record")
        action_id = str(record["action_id"])
        stage = str(record["stage"])
        run_id = record.get("run_id")
        if expected_run_id is not None and run_id != expected_run_id:
            raise ValueError(f"invalid lifecycle correlation: {action_id}")
        if run_id is not None and not str(run_id):
            raise ValueError("invalid lifecycle correlation")
        if "seq" in record and not isinstance(record["seq"], int):
            raise ValueError(f"invalid lifecycle correlation: {action_id}")
        if "timestamp" in record:
            try:
                timestamp = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError(f"malformed lifecycle record: {action_id}") from error
            if timestamp.tzinfo is None:
                raise ValueError(f"malformed lifecycle record: {action_id}")
        correlation = (run_id, record.get("seq"))
        if action_id in correlations and correlations[action_id] != correlation:
            raise ValueError(f"invalid lifecycle correlation: {action_id}")
        correlations[action_id] = correlation
        stages = grouped.setdefault(action_id, [])
        if stage not in order or stage in stages:
            raise ValueError(f"invalid lifecycle sequence: {action_id}/{stage}")
        stages.append(stage)
    expected = list(LIFECYCLE_STAGES)
    for action_id, stages in grouped.items():
        if stages == ["proposed", "policy_decision"]:
            decision = next(
                (str(record.get("decision")) for record in records
                 if str(record.get("action_id")) == action_id
                 and record.get("stage") == "policy_decision"),
                None,
            )
            if decision in {"allow", "deny"} or decision is None:
                continue

        if stages == ["proposed", "policy_decision", "observed", "executed"]:
            continue
        if stages != expected:
            raise ValueError(f"incomplete lifecycle sequence: {action_id}")