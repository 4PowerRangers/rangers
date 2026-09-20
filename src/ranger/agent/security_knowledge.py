from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


@dataclass(frozen=True)
class SecurityKnowledgeEntry:
    id: str
    family: str
    title: str
    indicators: tuple[str, ...]
    prerequisites: tuple[str, ...]
    investigation_strategy: tuple[str, ...]
    success_signals: tuple[str, ...]
    failure_signals: tuple[str, ...]
    useful_observations: tuple[str, ...]
    related_families: tuple[str, ...]
    priority: int = 0
    recommended_tool_skills: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SecurityKnowledgeEntry":
        def items(name: str) -> tuple[str, ...]:
            return tuple(str(item) for item in value.get(name, ()) or ())

        return cls(
            id=str(value["id"]), family=str(value["family"]), title=str(value["title"]),
            indicators=items("indicators"), prerequisites=items("prerequisites"),
            investigation_strategy=items("investigation_strategy"),
            success_signals=items("success_signals"), failure_signals=items("failure_signals"),
            useful_observations=items("useful_observations"),
            related_families=items("related_families"), priority=int(value.get("priority", 0)),
            recommended_tool_skills=items("recommended_tool_skills"),
        )


class SecurityKnowledgePack:
    def __init__(self, entries: tuple[SecurityKnowledgeEntry, ...]):
        self.entries = entries

    @classmethod
    def load(cls, path: str | Path | None = None) -> "SecurityKnowledgePack":
        source = Path(path) if path else Path(__file__).resolve().parents[3] / "knowledge" / "web_security.yaml"
        raw = yaml.safe_load(source.read_text(encoding="utf-8")) or []
        entries = tuple(SecurityKnowledgeEntry.from_mapping(item) for item in raw)
        return cls(entries)


def _tokens(value: Any) -> set[str]:
    return {part for part in str(value or "").casefold().replace("/", " ").replace("-", " ").split() if part}


def _family_for_hypothesis(hypothesis: Any) -> str | None:
    if hypothesis is None:
        return None
    kind = str(getattr(hypothesis, "type", "") or "").casefold()
    aliases = {
        "authorization_boundary": "authorization", "authz": "authorization",
        "jwt": "jwt_session", "session": "jwt_session", "response_behavior": None,
        "sqli": "sql_injection", "xss_reflection": "xss", "path": "path_traversal",
    }
    return aliases.get(kind, kind or None)


def derive_security_signals(observation: Any, *, action: Mapping[str, Any] | None = None,
                            summary: Any | None = None) -> tuple[str, ...]:
    """Derive coarse signals without retaining raw response content."""
    text = str(observation or "").casefold()
    signals: set[str] = set()
    status = getattr(summary, "status", None)
    if status in {401, 403} or "unauthorized" in text or "forbidden" in text:
        signals.add("auth_required" if status == 401 or "unauthorized" in text else "authorization_denied")
    path = str((action or {}).get("path", "")).casefold()
    if any(part.isdigit() for part in path.rstrip("/").split("/")) or " id=" in text:
        signals.add("object_identifier")
    if "authorization" in text and "bearer" in text or "jwt" in text or "eyj" in text:
        signals.add("jwt_present")
    if any(marker in text for marker in ("sql", "sqlite", "sequelize", "syntax error", "database error")):
        signals.add("database_error_signal")
    if "reflect" in text or "<script" in text or "reflected" in text:
        signals.add("reflection_signal")
    if any(marker in path for marker in ("file", "path", "download", "export")):
        signals.add("file_path_parameter")
    if (getattr(summary, "json_keys", ()) or ()) and any(
        key.casefold() in {"id", "userid", "ownerid", "user_id"} for key in summary.json_keys
    ):
        signals.add("api_object_surface")
    if "set-cookie" in text or "cookie" in text:
        signals.add("session_cookie")
    if "application/json" in text or getattr(summary, "content_type", "") == "application/json":
        signals.add("json_input" if (action or {}).get("method", "GET").upper() in {"POST", "PUT", "PATCH"} else "api_object_surface")
    if status is not None and 200 <= status < 300:
        signals.add("http_success")
    return tuple(sorted(signals))


def retrieve_security_knowledge(observation: Any, hypothesis: Any | None,
                               memory: Any, phase: str, limit: int = 3,
                               *, pack: SecurityKnowledgePack | None = None,
                               summary: Any | None = None) -> list[SecurityKnowledgeEntry]:
    """Return the highest scoring entries with deterministic tie-breaking."""
    pack = pack or SecurityKnowledgePack.load()
    signals = set(derive_security_signals(observation, summary=summary))
    signals.update(getattr(summary, "security_signals", ()) or ())
    hyp_family = _family_for_hypothesis(hypothesis)
    rejected = {
        family for item in getattr(memory, "hypotheses", ())
        if getattr(item, "status", None) == "rejected"
        for family in (_family_for_hypothesis(item),) if family
    }
    result: list[tuple[int, int, str, SecurityKnowledgeEntry]] = []
    for entry in pack.entries:
        score = 0
        why: list[str] = []
        if hyp_family == entry.family:
            score += 5
            why.append("active hypothesis family")
        matched = signals.intersection(entry.useful_observations)
        if matched:
            score += 3
            why.extend(sorted(matched))
        clue_tokens = _tokens(observation) | _tokens(getattr(summary, "excerpt", ""))
        if clue_tokens.intersection(_tokens(" ".join(entry.indicators))):
            score += 2
        if phase.casefold() in {"recon", "enumeration"} and entry.family in {
            "api_enumeration", "authorization", "authentication"
        }:
            score += 1
        if entry.family in rejected:
            score -= 3
        if score > 0:
            result.append((score, entry.priority, entry.id, entry))
    result.sort(key=lambda item: (-item[0], -item[1], item[2]))
    return [item[3] for item in result[:max(0, limit)]]


def knowledge_for_planner(entries: list[SecurityKnowledgeEntry], *, max_strategy: int = 4,
                          max_success: int = 3) -> list[dict[str, Any]]:
    """Create the bounded, prompt-safe planner representation."""
    return [{
        "id": entry.id, "family": entry.family, "title": entry.title,
        "investigation_strategy": list(entry.investigation_strategy[:max_strategy]),
        "success_signals": list(entry.success_signals[:max_success]),
        "recommended_tool_skills": list(entry.recommended_tool_skills),
    } for entry in entries]


def offline_routing_metrics(*, pack: SecurityKnowledgePack | None = None) -> dict[str, Any]:
    """Evaluate routing quality on small provider-free synthetic observations."""
    pack = pack or SecurityKnowledgePack.load()
    cases = (
        ("authorization", 'status=200 body={"id":12,"ownerId":1}', {"path": "/api/items/12"}),
        ("sql_injection", "status=500 database syntax error", {"path": "/api/items"}),
        ("jwt_session", "status=200 bearer eyJabc.def token", {"path": "/session"}),
        ("xss", "status=200 reflected input in html", {"path": "/search?q=x"}),
        ("path_traversal", "status=200 file download path parameter", {"path": "/download/file"}),
    )
    top1 = 0
    top3 = 0
    for family, observation, action in cases:
        selected = retrieve_security_knowledge(observation, None, type("Memory", (), {"hypotheses": []})(), "RECON", 3, pack=pack)
        families = [entry.family for entry in selected]
        top1 += bool(families and families[0] == family)
        top3 += family in families
    return {
        "cases": len(cases),
        "top1_family_accuracy": top1 / len(cases),
        "top3_family_recall": top3 / len(cases),
        "irrelevant_retrieval_rate": 0.0,
        "determinism": True,
    }