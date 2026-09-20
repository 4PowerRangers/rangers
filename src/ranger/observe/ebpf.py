"""eBPF observer; seq belongs to the event start, not normalization time."""

from typing import Any, Mapping

from .normalizer import Observer, RawObservation, normalize_attributes
from ..core.event import Event


class EbpfObserver(Observer):
    """Base adapter for eBPF sources; concrete source mapping is intentionally deferred."""

    def normalize(self, run_id: str, observation: RawObservation, *, seq: int) -> Event:
        return Event(
            schema_version="0.2",
            run_id=run_id,
            timestamp=observation.timestamp,
            actor=observation.actor,
            source=observation.source,
            kind=observation.kind,
            action=observation.action,
            target=observation.target,
            seq=seq,
            attributes=normalize_attributes(observation.facts),
        )

    def from_tetragon(self, run_id: str, payload: Mapping[str, Any]) -> Event:
        """Experimental/deferred Tetragon adapter compatibility surface."""
        raise NotImplementedError("Tetragon field mapping is not implemented yet")

    def from_falco(self, run_id: str, payload: Mapping[str, Any]) -> Event:
        """Experimental/deferred Falco adapter compatibility surface."""
        raise NotImplementedError("Falco field mapping is not implemented yet")
