from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
import warnings

from .identity import event_id as make_event_id


@dataclass(frozen=True)
class Event:
    schema_version: str
    run_id: str
    timestamp: datetime
    actor: str
    source: str
    kind: str
    action: str
    target: str
    seq: int = -1
    attributes: dict[str, Any] = field(default_factory=dict)
    event_id: str | None = None

    def __post_init__(self) -> None:
        if not self.schema_version or not self.run_id:
            raise ValueError("schema_version and run_id are required")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        if not isinstance(self.attributes, dict):
            raise TypeError("attributes must be a dictionary")
        if self.seq < 0:
            raise ValueError("new events require seq >= 0")

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "source": self.source,
            "kind": self.kind,
            "action": self.action,
            "target": self.target,
            "seq": self.seq,
            "attributes": self.attributes,
        }
        resolved_event_id = self.event_id or (make_event_id(self.seq) if self.seq >= 0 else None)
        if resolved_event_id is not None:
            data["event_id"] = resolved_event_id
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Event":
        timestamp = data["timestamp"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        schema_version = str(data["schema_version"])
        seq = data.get("seq")
        legacy = seq is None
        if legacy:
            if schema_version != "0.1":
                raise ValueError("event schema requires seq")
            seq = 0
            warnings.warn(
                "legacy event without seq loaded; ordering semantics are unavailable",
                UserWarning,
                stacklevel=2,
            )
        event = cls(
            schema_version=schema_version,
            run_id=str(data["run_id"]),
            timestamp=timestamp,
            actor=str(data["actor"]),
            source=str(data["source"]),
            kind=str(data["kind"]),
            action=str(data["action"]),
            target=str(data["target"]),
            seq=int(seq),
            attributes=dict(data.get("attributes", {})),
            event_id=(data.get("event_id") or (make_event_id(int(seq)) if not legacy else None)),
        )
        if legacy:
            object.__setattr__(event, "seq", -1)
        return event

    @classmethod
    def now(cls, *, run_id: str, actor: str, source: str, kind: str,
            action: str, target: str, seq: int, attributes: Mapping[str, Any] | None = None,
            event_id: str | None = None) -> "Event":
        return cls(
            schema_version="0.2",
            run_id=run_id,
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            source=source,
            kind=kind,
            action=action,
            target=target,
            seq=seq,
            attributes=dict(attributes or {}),
            event_id=event_id or (make_event_id(seq) if seq >= 0 else None),
        )