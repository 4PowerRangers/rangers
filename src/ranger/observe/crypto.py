"""Small, redaction-safe crypto semantics used by scenario observers."""

from dataclasses import dataclass
import re
from typing import Any, Mapping


@dataclass(frozen=True)
class CryptoArtifact:
    type: str
    source: str
    ownership: str


@dataclass(frozen=True)
class CryptoEncoding:
    layers: tuple[str, ...]
    decoded_locally: bool


@dataclass(frozen=True)
class CryptoField:
    path: str
    semantic_context: str


@dataclass(frozen=True)
class CryptoObservation:
    representation: str
    field: str
    usage_context: str
    primitive: str
    confidence: str
    implementation_evidence: tuple[str, ...]


@dataclass(frozen=True)
class CryptoFinding:
    category: str
    primitive: str | None
    confidence: str
    evidence_fingerprint: str


def classify_crypto_finding(observation: CryptoObservation) -> CryptoFinding:
    evidence = tuple(sorted(set(observation.implementation_evidence)))
    enough = {
        "digest_format", "application_hash_implementation", "password_field_context",
    }.issubset(evidence)
    confirmed = (
        observation.representation in {"32_lowercase_hex", "32-hex"}
        and observation.primitive.casefold() == "md5"
        and observation.usage_context == "password_hashing"
        and enough
    )
    return CryptoFinding(
        category="deprecated_insecure_password_hashing" if confirmed else "partialunclassified",
        primitive="MD5" if confirmed else None,
        confidence=observation.confidence if confirmed else "low",
        evidence_fingerprint="crypto:" + ":".join(evidence),
    )


def crypto_observation_from_mapping(data: Mapping[str, Any]) -> CryptoObservation:
    """Build an observation from metadata; never retains the observed value."""
    return CryptoObservation(
        representation=str(data.get("representation", "unknown")),
        field=str(data.get("field", "unknown")),
        usage_context=str(data.get("usage_context", "unknown")),
        primitive=str(data.get("primitive", "ambiguous")),
        confidence=str(data.get("confidence", "low")),
        implementation_evidence=tuple(str(item) for item in data.get("implementation_evidence", ())),
    )


def inspect_password_field(payload: Mapping[str, Any], *, implementation_evidence: tuple[str, ...] = ()) -> dict[str, Any] | None:
    """Inspect ``data.password`` while returning metadata rather than its value."""
    data = payload.get("data")
    value = data.get("password") if isinstance(data, Mapping) else None
    if not isinstance(value, str):
        return None
    representation = "32_lowercase_hex" if re.fullmatch(r"[0-9a-f]{32}", value) else "other"
    observation = CryptoObservation(
        representation, "data.password", "password_hashing", "ambiguous", "medium",
        implementation_evidence or ("digest_format", "password_field_context"),
    )
    finding = classify_crypto_finding(observation)
    return {
        "artifact": {"type": "authentication_token_payload", "source": "own_login_response", "ownership": "own"},
        "encoding": {"layers": ["jwt_payload", "json"], "decoded_locally": True},
        "field": {"path": observation.field, "semantic_context": observation.usage_context},
        "crypto": {"representation": representation, "primitive": finding.primitive,
                   "confidence": finding.confidence, "evidence_fingerprint": finding.evidence_fingerprint},
        "finding": {"category": finding.category},
    }
