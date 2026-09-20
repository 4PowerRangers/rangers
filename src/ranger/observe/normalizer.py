"""Observer extension contract."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping
import warnings

from ..core.event import Event


@dataclass(frozen=True)
class RawObservation:
    timestamp: datetime
    actor: str
    source: str
    kind: str
    action: str
    target: str
    facts: Mapping[str, Any] = field(default_factory=dict)


def normalize_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize shared event attributes before constructing an ``Event``.

    Ports are represented as integers in normalized events. Invalid values are
    retained for the evaluator's defensive handling and reported as warnings.
    """
    normalized = dict(attributes)
    if "port" in normalized and normalized["port"] is not None:
        try:
            normalized["port"] = int(normalized["port"])
        except (TypeError, ValueError):
            warnings.warn(
                f"invalid port value ignored during normalization: {normalized['port']!r}",
                UserWarning,
                stacklevel=2,
            )
    return normalized


class Observer(ABC):
    """Normalizes source facts without evaluating their meaning."""

    @abstractmethod
    def normalize(self, run_id: str, observation: RawObservation, *, seq: int) -> Event:
        raise NotImplementedError
