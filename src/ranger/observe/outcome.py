"""Trusted before/after state observation for realized outcomes."""

from dataclasses import replace
import hashlib
import json
from typing import Any, Mapping

from ..core.event import Event


class TrustedOutcomeObserver:
    """Derive outcomes only from an explicit trusted state before/after pair."""

    def attach(
        self,
        event: Event,
        *,
        before: Any,
        after: Any,
        entity: str,
        resource: str,
        source: str,
    ) -> Event:
        evidence = self.observe(
            action_id=event.attributes.get("action_id"),
            seq=event.seq,
            before=before,
            after=after,
            entity=entity,
            resource=resource,
            source=source,
        )
        attributes = dict(event.attributes)
        existing = attributes.get("outcome_evidence")
        if isinstance(existing, Mapping):
            attributes["outcome_evidence"] = [existing, evidence]
        elif isinstance(existing, list):
            attributes["outcome_evidence"] = [*existing, evidence]
        else:
            attributes["outcome_evidence"] = evidence
        if evidence["realized_outcome"] is not None:
            attributes["realized_outcome"] = evidence["realized_outcome"]
        return replace(event, attributes=attributes)

    @staticmethod
    def observe(
        *,
        action_id: str | None,
        seq: int | None = None,
        before: Any,
        after: Any,
        entity: str,
        resource: str,
        source: str,
    ) -> dict[str, Any]:
        outcome: str | None = None
        changed_fields: list[str] = []
        status = "unclassified"
        confidence = "none"
        if before is not None and after is None:
            outcome = "record_deleted"
            changed_fields = ["__record__"]
            status = "confirmed"
            confidence = "high"
        elif _is_absent(before) and _is_identifiable_created_record(after):
            outcome = "record_created"
            changed_fields = ["__record__"]
            status = "confirmed"
            confidence = "high"
        elif before is not None and after is not None:
            changed_fields = _changed_fields(before, after)
            if not changed_fields:
                status = "no_change"
                confidence = "high"
        return {
            "action_id": action_id,
            "seq": seq,
            "evidence_type": "state_transition",
            "source": source,
            "source_provenance": source,
            "trust_level": "trusted",
            "entity": entity,
            "resource": resource,
            "before_hash": _hash_value(before),
            "after_hash": _hash_value(after),
            "changed_fields": changed_fields,
            "realized_outcome": outcome,
            "confidence": confidence,
            "status": status,
        }


def _is_absent(value: Any) -> bool:
    return value is None or isinstance(value, (list, tuple)) and not value


def _is_identifiable_created_record(value: Any) -> bool:
    if isinstance(value, Mapping):
        return _record_identity(value) is not None
    if isinstance(value, (list, tuple)):
        return len(value) == 1 and isinstance(value[0], Mapping) and _record_identity(value[0]) is not None
    return False


def _record_identity(record: Mapping[str, Any]) -> tuple[str, Any] | None:
    for key in ("id", "_id", "uuid", "key"):
        value = record.get(key)
        if value is not None:
            return key, value
    return None


def _hash_value(value: Any) -> str | None:
    if value is None:
        return None
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _changed_fields(before: Any, after: Any) -> list[str]:
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        return sorted({str(key) for key in set(before) | set(after) if before.get(key) != after.get(key)})
    return ["__value__"] if before != after else []
