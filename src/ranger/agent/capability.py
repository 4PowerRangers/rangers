from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

from .security_knowledge import (
    SecurityKnowledgePack,
    knowledge_for_planner,
    retrieve_security_knowledge,
)
from .tool_skills import recommend_tool_skills


_PHASES = ("RECON", "ENUMERATION", "HYPOTHESIS_TEST", "EXPLOIT", "VERIFY", "REPORT")
_MAX_EXCERPT = 400
_ENDPOINT_RE = re.compile(r"(?<![A-Za-z0-9])(/[A-Za-z0-9_./:{}-]{1,180})")


def _fingerprint_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class EndpointFinding:
    path: str
    method: str | None = None
    status: int | None = None
    source: str = "observation"
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class CredentialFinding:
    kind: str
    identifier: str
    status: str = "observed"


@dataclass(frozen=True)
class TokenFinding:
    kind: str
    fingerprint: str
    status: str = "current"


@dataclass
class Hypothesis:
    id: str
    type: str
    target: str | None
    rationale: str
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttemptRecord:
    fingerprint: str
    method: str | None
    path: str | None
    hypothesis_id: str | None
    status: str
    step: int
    reason: str | None = None


@dataclass(frozen=True)
class ObservationRecord:
    step: int
    action_id: str | None
    summary: Mapping[str, Any]


@dataclass(frozen=True)
class ObservationSummary:
    status: int | None = None
    content_type: str | None = None
    response_size: int | None = None
    json_keys: tuple[str, ...] = ()
    discovered_links: tuple[str, ...] = ()
    discovered_endpoints: tuple[str, ...] = ()
    interesting_headers: tuple[str, ...] = ()
    auth_state: str | None = None
    error_signals: tuple[str, ...] = ()
    success_signals: tuple[str, ...] = ()
    reflection_signals: tuple[str, ...] = ()
    security_signals: tuple[str, ...] = ()
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "json_keys": list(self.json_keys),
            "discovered_links": list(self.discovered_links),
            "discovered_endpoints": list(self.discovered_endpoints),
            "interesting_headers": list(self.interesting_headers),
            "error_signals": list(self.error_signals),
            "success_signals": list(self.success_signals),
            "reflection_signals": list(self.reflection_signals),
            "security_signals": list(self.security_signals),
        }


@dataclass(frozen=True)
class Progress:
    objective_understood: bool = False
    attack_surface_found: bool = False
    vulnerability_hypothesis_found: bool = False
    exploit_signal_observed: bool = False
    goal_evidence_observed: bool = False

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)


@dataclass
class AgentState:
    """Serializable top-level state view exposed to the planner/trace."""

    objective: str
    current_phase: str
    observations: list[Mapping[str, Any]] = field(default_factory=list)
    discovered_endpoints: list[Mapping[str, Any]] = field(default_factory=list)
    discovered_parameters: dict[str, list[str]] = field(default_factory=dict)
    credentials: list[Mapping[str, Any]] = field(default_factory=list)
    tokens: list[Mapping[str, Any]] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    interesting_responses: list[Mapping[str, Any]] = field(default_factory=list)
    hypotheses: list[Mapping[str, Any]] = field(default_factory=list)
    attempted_actions: list[Mapping[str, Any]] = field(default_factory=list)
    failed_actions: list[Mapping[str, Any]] = field(default_factory=list)
    successful_actions: list[str] = field(default_factory=list)
    progress: Mapping[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentMemory:
    endpoints: list[EndpointFinding] = field(default_factory=list)
    parameters: dict[str, set[str]] = field(default_factory=dict)
    credentials: list[CredentialFinding] = field(default_factory=list)
    tokens: list[TokenFinding] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    session_tokens: dict[str, str] = field(default_factory=dict)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    completed_steps: list[str] = field(default_factory=list)
    failed_attempts: list[AttemptRecord] = field(default_factory=list)
    useful_observations: list[ObservationRecord] = field(default_factory=list)
    progress: Progress = field(default_factory=Progress)

    def fingerprint(self, action: Mapping[str, Any], hypothesis_id: str | None = None) -> str:
        body = action.get("body", action.get("json", action.get("data")))
        if isinstance(body, Mapping):
            body_shape: Any = sorted(str(key) for key in body)
        elif isinstance(body, str):
            try:
                parsed = json.loads(body)
            except (TypeError, ValueError):
                body_shape = "text"
            else:
                body_shape = sorted(str(key) for key in parsed) if isinstance(parsed, Mapping) else type(parsed).__name__
        else:
            body_shape = None
        path = str(action.get("path", action.get("url", "")))
        parsed = urlsplit(path)
        query_shape = sorted(key for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
        payload = {
            "method": str(action.get("method", "")).upper(),
            "path": parsed.path or path,
            "query": query_shape,
            "body": body_shape,
            "hypothesis_id": hypothesis_id,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]

    def already_attempted(self, fingerprint: str) -> bool:
        return any(item.fingerprint == fingerprint for item in self.failed_attempts)

    def record_attempt(self, action: Mapping[str, Any], *, step: int,
                       status: str, hypothesis_id: str | None = None,
                       reason: str | None = None) -> str:
        fingerprint = self.fingerprint(action, hypothesis_id)
        method = str(action.get("method")).upper() if action.get("method") else None
        path = str(action.get("path")) if action.get("path") is not None else None
        item = AttemptRecord(fingerprint, method, path, hypothesis_id, status, step, reason)
        if status in {"failed", "blocked", "denied"}:
            self.failed_attempts.append(item)
        if status in {"succeeded", "completed"}:
            self.completed_steps.append(f"step-{step}:{method or action.get('action')}")
        return fingerprint

    def update_observation(self, summary: ObservationSummary, *, step: int,
                           action_id: str | None, action: Mapping[str, Any] | None = None) -> None:
        data = summary.to_dict()
        self.useful_observations.append(ObservationRecord(step, action_id, data))
        method = str((action or {}).get("method", "GET")).upper()
        if action:
            self._record_parameters(action)
        from .tool_skills import extract_cookies, extract_endpoints, extract_tokens

        self.cookies.update(extract_cookies(summary.excerpt))
        extracted_tokens = extract_tokens(summary.excerpt)
        self.session_tokens.update(extracted_tokens)
        for token in extracted_tokens.values():
            self._add_unique_token(TokenFinding("observed_token", _fingerprint_secret(token)))
        if summary.auth_state:
            self._add_unique_credential(CredentialFinding("auth_state", summary.auth_state))
        for match in re.findall(r"(?:token|jwt)[=: ]+([A-Za-z0-9._-]{8,})", summary.excerpt, re.I):
            self._add_unique_token(TokenFinding("observed_token", _fingerprint_secret(match)))
        for path in (*summary.discovered_endpoints, *extract_endpoints(summary.excerpt)):
            finding = EndpointFinding(path, method, summary.status)
            if not any(item.path == path and item.method == method for item in self.endpoints):
                self.endpoints.append(finding)
        if action and isinstance(action.get("path"), str):
            path = action["path"]
            if not any(item.path == path and item.method == method for item in self.endpoints):
                self.endpoints.append(EndpointFinding(path, method, summary.status, "action"))
        if summary.status in {401, 403}:
            self._ensure_hypothesis("authorization_boundary", action, "authorization failure observed", 0.45)
        elif summary.status is not None and 200 <= summary.status < 300:
            self._ensure_hypothesis("response_behavior", action, "successful response observed", 0.35)
        for hypothesis in self.hypotheses:
            if hypothesis.status != "active":
                continue
            if action and hypothesis.target == action.get("path") and (
                (summary.status is not None and 200 <= summary.status < 300)
                or summary.auth_state == "unauthenticated"
            ):
                hypothesis.status = "supported"
                hypothesis.evidence.append(f"step-{step}:status={summary.status}")
        self._update_progress(summary)

    def record_tool_result(self, skill_id: str, result: Any, *, step: int) -> None:
        """Merge a tool-skill result into bounded memory without raw retention."""
        from .tool_skills import extract_cookies, extract_endpoints, extract_tokens

        if skill_id == "COOKIE_EXTRACT":
            self.cookies.update(extract_cookies(result))
        elif skill_id == "TOKEN_EXTRACT":
            extracted = extract_tokens(result)
            self.session_tokens.update(extracted)
            for token in extracted.values():
                self._add_unique_token(TokenFinding("observed_token", _fingerprint_secret(token)))
        elif skill_id in {"ENDPOINT_EXTRACT", "LINK_EXTRACT"}:
            for path in extract_endpoints(result):
                if not any(item.path == path for item in self.endpoints):
                    self.endpoints.append(EndpointFinding(path, source="tool_skill"))
        elif skill_id == "RESPONSE_COMPARE" and self.hypotheses:
            active = next((item for item in reversed(self.hypotheses) if item.status == "active"), None)
            if active and isinstance(result, Mapping):
                changed = [key for key, value in result.items() if key.endswith("changed") and value]
                if changed:
                    active.evidence.append(f"step-{step}:response_diff={','.join(sorted(changed))}")

    def _record_parameters(self, action: Mapping[str, Any]) -> None:
        path = str(action.get("path", ""))
        parsed = urlsplit(path)
        keys = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        body = action.get("body", action.get("json", action.get("data")))
        if isinstance(body, Mapping):
            keys.update(str(key) for key in body)
        if keys:
            self.parameters.setdefault(parsed.path or path, set()).update(keys)

    def _add_unique_credential(self, finding: CredentialFinding) -> None:
        if not any(item.kind == finding.kind and item.identifier == finding.identifier for item in self.credentials):
            self.credentials.append(finding)

    def _add_unique_token(self, finding: TokenFinding) -> None:
        if not any(item.fingerprint == finding.fingerprint for item in self.tokens):
            self.tokens.append(finding)

    def _ensure_hypothesis(self, kind: str, action: Mapping[str, Any] | None,
                           rationale: str, confidence: float) -> None:
        target = str((action or {}).get("path")) if (action or {}).get("path") else None
        if any(item.type == kind and item.target == target and item.status == "active" for item in self.hypotheses):
            return
        ident = f"hyp-{len(self.hypotheses) + 1:02d}"
        self.hypotheses.append(Hypothesis(ident, kind, target, rationale, confidence=confidence))

    def _update_progress(self, summary: ObservationSummary) -> None:
        old = self.progress
        success = bool(summary.success_signals)
        goal = any(signal in {"goal_state_achieved", "designated_outcome"} for signal in summary.success_signals)
        self.progress = Progress(
            objective_understood=True,
            attack_surface_found=old.attack_surface_found or bool(summary.discovered_endpoints),
            vulnerability_hypothesis_found=old.vulnerability_hypothesis_found or bool(self.hypotheses),
            exploit_signal_observed=old.exploit_signal_observed or success,
            goal_evidence_observed=old.goal_evidence_observed or goal,
        )

    def to_context(self, *, max_observations: int = 8, max_hypotheses: int = 5,
                   max_failed_attempts: int = 8) -> dict[str, Any]:
        active = [item.to_dict() for item in self.hypotheses if item.status == "active"][-max_hypotheses:]
        return {
            "endpoints": [asdict(item) for item in self.endpoints[-50:]],
            "parameters": {key: sorted(values) for key, values in list(self.parameters.items())[-50:]},
            "credentials": [asdict(item) for item in self.credentials[-10:]],
            "tokens": [asdict(item) for item in self.tokens[-10:]],
            "cookies": {key: "[redacted]" for key in self.cookies},
            "hypotheses": active,
            "completed_steps": self.completed_steps[-20:],
            "failed_attempts": [asdict(item) for item in self.failed_attempts[-max_failed_attempts:]],
            "useful_observations": [asdict(item) for item in self.useful_observations[-max_observations:]],
            "progress": self.progress.to_dict(),
        }

    def state(self, *, objective: str, phase: str) -> AgentState:
        context = self.to_context()
        return AgentState(
            objective=objective,
            current_phase=phase,
            observations=context["useful_observations"],
            discovered_endpoints=context["endpoints"],
            discovered_parameters=context["parameters"],
            credentials=context["credentials"],
            tokens=context["tokens"],
            cookies=context["cookies"],
            interesting_responses=context["useful_observations"],
            hypotheses=context["hypotheses"],
            attempted_actions=(context["failed_attempts"] + [
                {"action": item, "status": "succeeded"}
                for item in context["completed_steps"]
            ]),
            failed_actions=context["failed_attempts"],
            successful_actions=context["completed_steps"],
            progress=context["progress"],
        )


@dataclass(frozen=True)
class PlannerPlan:
    phase: str
    hypothesis_id: str | None
    reason: str
    next_action_goal: str
    expected_signal: str
    tool_skill: str | None = None
    tool_strategy: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CapabilityPlanner:
    """Deterministic phase/planning layer; it does not encode an exploit."""

    def __init__(self, objective: str | None = None):
        self.objective = objective or "complete the assigned objective with evidence"
        self.phase = "RECON"
        self.plan = PlannerPlan("RECON", None, "initial observation and attack-surface discovery",
                                "identify the next useful endpoint or response signal",
                                "an endpoint, link, status, or authentication signal", "HTTP_REQUEST")

    def _rank_active_hypotheses(self, memory: AgentMemory) -> list[Hypothesis]:
        """Rank hypotheses with stable, inspectable evidence-based weights."""
        def score(item: Hypothesis) -> tuple[float, int, str]:
            failures = sum(1 for attempt in memory.failed_attempts
                           if attempt.hypothesis_id == item.id)
            supported = 3.0 if item.status == "supported" else 0.0
            return (
                item.confidence * 10.0 + len(item.evidence) * 2.0 + supported - failures,
                -len(item.id), item.id,
            )

        return sorted((item for item in memory.hypotheses if item.status in {"active", "supported"}),
                      key=score, reverse=True)

    def update(self, memory: AgentMemory, *, last_summary: ObservationSummary | None = None,
               last_status: str | None = None) -> PlannerPlan:
        progress = memory.progress
        ranked = self._rank_active_hypotheses(memory)
        active = ranked[0] if ranked else None
        if progress.goal_evidence_observed:
            phase = "REPORT"
            reason = "goal evidence is present; preserve evidence and stop unnecessary exploration"
            goal = "verify the goal evidence and halt"
            signal = "stable goal evidence"
        elif active and (last_status in {"failed", "blocked", "denied"}):
            active.status = "rejected"
            phase = "RECON" if not memory.endpoints else "HYPOTHESIS_TEST"
            reason = "the latest attempt did not support the active hypothesis"
            goal = "choose a materially different test for the remaining hypothesis"
            signal = "a different response or authorization boundary"
        elif active and progress.exploit_signal_observed:
            phase = "VERIFY"
            reason = "a useful response signal requires bounded verification"
            goal = "verify the signal with the smallest necessary follow-up"
            signal = "repeatable, goal-relevant evidence"
        elif active:
            phase = "HYPOTHESIS_TEST"
            reason = "test the active hypothesis instead of repeating a failed action"
            goal = "test the active hypothesis with a new action fingerprint"
            signal = "evidence supporting or rejecting the hypothesis"
        elif memory.endpoints:
            phase = "ENUMERATION"
            reason = "the attack surface contains candidate endpoints"
            goal = "select the next relevant endpoint without duplicating failed attempts"
            signal = "a response that narrows the hypothesis space"
        else:
            phase = "RECON"
            reason = "no useful attack-surface signal has been observed"
            goal = "discover a bounded, objective-relevant endpoint"
            signal = "an endpoint, link, status, or authentication signal"
        self.phase = phase
        signals = last_summary.security_signals if last_summary else ()
        family = active.type if active else None
        family = {"authorization_boundary": "authorization"}.get(family, family)
        skills = recommend_tool_skills(signals=signals, hypothesis_family=family)
        self.plan = PlannerPlan(
            phase, active.id if active else None, reason, goal, signal,
            skills[0] if skills else "HTTP_REQUEST",
            {"recommended": list(skills), "compare_to_previous": "RESPONSE_COMPARE" in skills},
        )
        return self.plan


def summarize_observation(observation: Any, *, action: Mapping[str, Any] | None = None) -> ObservationSummary:
    """Extract bounded facts from a tool result without retaining full raw data."""
    text = observation if isinstance(observation, str) else json.dumps(observation, ensure_ascii=False, default=str)
    status_match = re.search(r"(?:^|\n)status=(\d{3})", text)
    status = int(status_match.group(1)) if status_match else None
    size_match = re.search(r"(?:size|response_size)[=: ](\d+)", text, re.I)
    content_type_match = re.search(r"(?:content_type|content-type)[=: ]([^\n;]+)", text, re.I)
    endpoints = tuple(dict.fromkeys(match.group(1) for match in _ENDPOINT_RE.finditer(text)))
    links = tuple(item for item in endpoints if item != (action or {}).get("path"))
    json_keys: tuple[str, ...] = ()
    body_match = re.search(r"body(?:Preview| preview)?[=:](.*)", text, re.I | re.S)
    body = body_match.group(1).strip() if body_match else text
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, Mapping):
        json_keys = tuple(str(key) for key in list(parsed)[:40])
    lower = text.casefold()
    errors = []
    for marker, label in (("unauthorized", "authentication_required"),
                          ("authentication required", "authentication_required"),
                          ("forbidden", "authorization_denied"),
                          ("not found", "not_found"), ("timeout", "timeout"), ("error", "error")):
        if marker in lower and label not in errors:
            errors.append(label)
    success = []
    if status is not None and 200 <= status < 300:
        success.append("http_success")
    if "goal_state=achieved" in lower:
        success.append("goal_state_achieved")
    if "designated" in lower or "realized_outcome" in lower:
        success.append("designated_outcome")
    auth_state = None
    if "authentication_role=" in lower:
        auth_state = "authenticated"
    elif status in {401, 403} or "authentication_required" in errors:
        auth_state = "unauthenticated"
    reflection = ("reflected_input",) if "reflect" in lower else ()
    security_signals = set()
    if status in {401, 403}:
        security_signals.add("auth_required" if status == 401 else "authorization_denied")
    if any(part.isdigit() for part in str((action or {}).get("path", "")).rstrip("/").split("/")):
        security_signals.add("object_identifier")
    if any(marker in lower for marker in ("jwt", "bearer", "eyj")):
        security_signals.add("jwt_present")
    if any(marker in lower for marker in ("sql", "sqlite", "sequelize", "syntax error", "database error")):
        security_signals.add("database_error_signal")
    if "reflect" in lower or "<script" in lower:
        security_signals.add("reflection_signal")
    if any(marker in str((action or {}).get("path", "")).casefold()
           for marker in ("file", "path", "download")):
        security_signals.add("file_path_parameter")
    if any(key.casefold() in {"id", "userid", "ownerid", "user_id"} for key in json_keys):
        security_signals.add("api_object_surface")
    if "set-cookie" in lower or "cookie" in lower:
        security_signals.add("session_cookie")
    return ObservationSummary(
        status=status,
        content_type=content_type_match.group(1).strip() if content_type_match else None,
        response_size=int(size_match.group(1)) if size_match else None,
        json_keys=json_keys,
        discovered_links=links,
        discovered_endpoints=endpoints,
        interesting_headers=tuple(item for item in ("observer_feedback", "authentication_role") if item in lower),
        auth_state=auth_state,
        error_signals=tuple(errors),
        success_signals=tuple(dict.fromkeys(success)),
        reflection_signals=reflection,
        security_signals=tuple(sorted(security_signals)),
        excerpt=text[:_MAX_EXCERPT],
    )


class CapabilityV2:
    """Coordinator used by ``run_episode`` to keep planner state additive."""

    def __init__(self, objective: str | None = None, *, knowledge_enabled: bool = True,
                 tools_enabled: bool = True,
                 knowledge_pack: SecurityKnowledgePack | None = None):
        self.memory = AgentMemory()
        self.planner = CapabilityPlanner(objective)
        self.knowledge_enabled = knowledge_enabled
        self.tools_enabled = tools_enabled
        self.knowledge_pack = knowledge_pack or SecurityKnowledgePack.load()
        self._last_observation: ObservationSummary | None = None

    def _knowledge(self) -> tuple[list[Any], dict[str, Any]]:
        if not self.knowledge_enabled:
            return [], {"candidates": 0, "selected": [], "signals": []}
        active = next((item for item in reversed(self.memory.hypotheses)
                       if item.status == "active"), None)
        entries = retrieve_security_knowledge(
            self._last_observation or "", active, self.memory, self.planner.phase,
            limit=3, pack=self.knowledge_pack, summary=self._last_observation,
        )
        signals = list(self._last_observation.security_signals) if self._last_observation else []
        return entries, {"candidates": len(self.knowledge_pack.entries),
                         "selected": [entry.id for entry in entries], "signals": signals}

    def context(self, *, step: int, max_steps: int, gateway: str,
                policy_target: str | None = None) -> dict[str, Any]:
        entries, retrieval = self._knowledge()
        return {
            "gateway": gateway,
            "policy_target": policy_target,
            "planner": self.planner.plan.to_dict(),
            "memory": self.memory.to_context(),
            "progress": self.memory.progress.to_dict(),
            "relevant_security_knowledge": knowledge_for_planner(entries),
            "knowledge_retrieval": retrieval,
            "tool_skill": self.planner.plan.tool_skill if self.tools_enabled else None,
            "tool_strategy": self.planner.plan.tool_strategy if self.tools_enabled else {},
        }

    def plan_metadata(self, action: Mapping[str, Any] | None = None) -> dict[str, Any]:
        data = self.planner.plan.to_dict()
        entries, retrieval = self._knowledge()
        data["knowledge_ids"] = [entry.id for entry in entries]
        data["knowledge_retrieval"] = retrieval
        data["tool_skill"] = self.planner.plan.tool_skill if self.tools_enabled else None
        data["tool_strategy"] = self.planner.plan.tool_strategy if self.tools_enabled else {}
        if action is not None:
            fp = self.memory.fingerprint(action, self.planner.plan.hypothesis_id)
            data["attempt_fingerprint"] = fp
            data["already_attempted"] = self.memory.already_attempted(fp)
        return data

    def state(self) -> AgentState:
        return self.memory.state(objective=self.planner.objective, phase=self.planner.phase)

    def observe(self, observation: Any, *, step: int, action_id: str | None,
                action: Mapping[str, Any] | None = None) -> ObservationSummary:
        summary = summarize_observation(observation, action=action)
        self._last_observation = summary
        self.memory.update_observation(summary, step=step, action_id=action_id, action=action)
        self.planner.update(self.memory, last_summary=summary)
        return summary

    def action_result(self, action: Mapping[str, Any], *, step: int, status: str,
                     reason: str | None = None) -> None:
        self.memory.record_attempt(action, step=step, status=status,
                                   hypothesis_id=self.planner.plan.hypothesis_id, reason=reason)
        self.planner.update(self.memory, last_status=status)