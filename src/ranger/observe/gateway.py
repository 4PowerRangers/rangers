"""Web observer; allocate seq at request start, before the upstream call."""

import argparse
from contextlib import AbstractContextManager, nullcontext
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import requests
from flask import Flask, Response, request

from .normalizer import Observer, RawObservation, normalize_attributes
from ..core.event import Event
from ..core.lifecycle import LifecycleEvent
from ..core.run import RunConfig, RunStore
from ..core.sequence import SequenceAllocator
from ..core.identity import event_id as make_event_id, request_id as make_request_id
from ..normalize import classify_activity, normalize_action, normalize_request

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
DROP_RESPONSE_HEADERS = {
    "connection", "content-encoding", "content-length", "transfer-encoding"
}
OBSERVER_FEEDBACK_HEADER = "X-Ranger-Observer-Feedback"
EventSink = Callable[[Event], None]


def _generic_response_metadata(body: Any, content_type: Any = None) -> dict[str, Any]:
    """Derive reusable, value-minimizing evidence from an HTTP response.

    The observer records response shape and field names, never response values.
    Scenario goals can therefore prove that a response contained a required
    field without turning the generic observer into a data-exfiltration sink.
    """
    if body is None:
        return {"response_observed": False, "response_parse_status": "absent"}
    raw = body if isinstance(body, bytes) else str(body).encode("utf-8", "replace")
    metadata: dict[str, Any] = {
        "response_observed": True,
        "response_body_sha256": hashlib.sha256(raw).hexdigest(),
        "response_body_bytes": len(raw),
    }
    if not raw:
        metadata["response_parse_status"] = "empty"
        return metadata
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        metadata["response_parse_status"] = "non_json"
        return metadata
    if isinstance(parsed, Mapping):
        metadata.update({
            "response_parse_status": "json_object",
            "response_json_fields": sorted(str(key) for key in parsed),
            "response_json_field_count": len(parsed),
        })
    elif isinstance(parsed, list):
        metadata.update({
            "response_parse_status": "json_array",
            "response_json_fields": [],
            "response_json_item_count": len(parsed),
        })
    else:
        metadata.update({
            "response_parse_status": "json_scalar",
            "response_json_fields": [],
        })
    return metadata


def _safe_agent_feedback(event: Event) -> str:
    """Expose only low-sensitivity semantic state to the requesting agent."""
    attributes = event.attributes
    fields: list[str] = []
    outcome = attributes.get("realized_outcome")
    if isinstance(outcome, str) and re.fullmatch(r"[a-z0-9_]{1,80}", outcome):
        fields.append(f"outcome={outcome}")
        fields.append("verification_state=confirmed")
    role = attributes.get("authentication_role")
    authentication = attributes.get("authentication")
    if not isinstance(role, str) and isinstance(authentication, Mapping):
        claims = authentication.get("claims")
        data = claims.get("data") if isinstance(claims, Mapping) else None
        role = data.get("role") if isinstance(data, Mapping) else None
    if isinstance(role, str) and re.fullmatch(r"[a-z0-9_-]{1,40}", role):
        fields.append(f"authentication_role={role}")
        fields.append("authentication_state=admin_session_established" if role == "admin" else "authentication_state=authenticated_session_established")
    for key in ("target_review_modified", "vulnerability_confirmed", "delay_budget_compliant"):
        value = attributes.get(key)
        if isinstance(value, bool):
            fields.append(f"{key}={str(value).lower()}")
    return ";".join(fields)


class ActionBindingRegistry:
    """Run-scoped, single-use server-issued action/request bindings."""

    def __init__(self, *, ttl_seconds: float = 60.0):
        self._ttl = ttl_seconds
        self._pending: dict[str, tuple[str, str, str, float]] = {}
        self._lock = threading.Lock()

    def register_invocation(self, run_id: str, action_id: str, decision: str) -> str:
        return self.register(run_id, action_id, decision)

    def consume_invocation(self, run_id: str, action_id: str, token: str) -> tuple[bool, str | None]:
        with self._lock:
            self._cleanup()
            binding = self._pending.get(token)
        if binding is None:
            return False, "missing_or_expired_invocation"
        if binding[:3] != (run_id, action_id, "allow"):
            return False, "invalid_invocation"
        return True, None

    def register(self, run_id: str, action_id: str, decision: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._cleanup()
            self._pending[token] = (run_id, action_id, decision, time.monotonic() + self._ttl)
        return token

    def consume(self, run_id: str, action_id: str, token: str) -> tuple[bool, str | None]:
        with self._lock:
            self._cleanup()
            binding = self._pending.pop(token, None)
        if binding is None:
            return False, "missing_or_replayed_token"
        if binding[:3] != (run_id, action_id, "allow"):
            return False, "invalid_action_binding"
        return True, None

    def close(self, run_id: str, action_id: str) -> None:
        with self._lock:
            self._pending = {
                token: binding for token, binding in self._pending.items()
                if binding[:2] != (run_id, action_id)
            }

    def active_actions(self, run_id: str) -> list[str]:
        with self._lock:
            self._cleanup()
            return sorted({binding[1] for binding in self._pending.values()
                           if binding[0] == run_id and binding[2] == "allow"})

    def _cleanup(self) -> None:
        now = time.monotonic()
        self._pending = {
            token: binding for token, binding in self._pending.items() if binding[3] > now
        }


class WebObserver(Observer):
    def __init__(self, report_contract: Mapping[str, Any] | None = None,
                 classification_rules: list[Mapping[str, Any]] | None = None) -> None:
        self.report_contract = dict(report_contract or {})
        self.classification_rules = [dict(rule) for rule in (classification_rules or [])]
        self._rule_state: dict[str, dict[str, Any]] = {}

    def normalize(self, run_id: str, observation: RawObservation, *, seq: int) -> Event:
        attributes = {
            key: value for key, value in observation.facts.items()
            if not key.startswith("_")
        }
        attributes.update(_generic_response_metadata(
            observation.facts.get("_response_body"),
            observation.facts.get("response_content_type"),
        ))
        rule_facts = {**attributes,
                      "_request_body": observation.facts.get("_request_body", b""),
                      "_response_body": observation.facts.get("_response_body", b""),
                      "_request_markers": observation.facts.get("_request_markers", ()),
                      "_response_markers": observation.facts.get("_response_markers", ())}
        for rule in self.classification_rules:
            if _rule_matches(rule.get("when", {}), rule_facts):
                marker_source = rule.get("set_matched_markers")
                if marker_source:
                    attributes["matched_markers"] = list(
                        rule_facts.get(f"_{marker_source}_markers", ())
                    )
                state = rule.get("state")
                if state:
                    key = str(state.get("key", "default"))
                    pair = _request_json_values(rule_facts.get("_request_body", b""), state.get("fields", []))
                    previous = self._rule_state.get(key)
                    if pair and previous and pair != previous["pair"]:
                        attributes.update(state.get("else_set", {}))
                    elif pair:
                        count = (previous or {}).get("count", 0) + 1
                        self._rule_state[key] = {"pair": pair, "count": count}
                        attributes.update(state.get("set", {}))
                        attributes[state.get("count_field", "count")] = count
                    else:
                        attributes.update(state.get("else_set", {}))
                else:
                    attributes.update(rule.get("set", {}))
                if rule.get("stop"):
                    break
        if "operation" not in attributes:
            attributes["operation"] = {"GET": "read", "POST": "create", "PUT": "modify",
                                        "PATCH": "modify", "DELETE": "delete"}.get(
                                            str(attributes.get("method", "")).upper())
        normalized_request = normalize_request({
            **attributes,
            "target": observation.target,
            "body": observation.facts.get("_request_body"),
        })
        activity = classify_activity(normalized_request, {
            "activity": attributes.get("activity"),
        })
        attributes.update({
            "normalized_request": normalized_request,
            "headers": normalized_request["headers"],
            "query": normalized_request["query"],
            "activity": activity["activity"],
            "activity_classification": activity["classification"],
            "activity_evidence_markers": activity["evidence_markers"],
        })
        if self.report_contract and "outcome_evidence" not in attributes:
            from .report import observe_report_acceptance
            raw_facts = dict(observation.facts)
            report = observe_report_acceptance(
                {**raw_facts, **attributes, "seq": seq, "target_executed": True}, self.report_contract,
            )
            if report["designated_endpoint"]:
                attributes["action"] = "report"
                attributes["report_accepted"] = report["report_accepted"]
                attributes["trusted_report_evidence"] = report["trusted_report_evidence"]
                attributes["outcome_evidence"] = report
                attributes.update(report.get("semantic_attributes", {}))
                if report["realized_outcome"]:
                    attributes["realized_outcome"] = report["realized_outcome"]
        return Event(
            schema_version="0.2",
            run_id=run_id,
            timestamp=observation.timestamp,
            actor=observation.actor,
            source="gateway",
            kind="web",
            action=attributes.pop("action", "request"),
            target=(self.report_contract.get("target", observation.target)
                    if self.report_contract and attributes.get("path") == self.report_contract.get("path")
                    else observation.target),
            seq=seq,
            attributes=normalize_attributes(attributes),
            event_id=make_event_id(seq) if seq >= 0 else None,
        )


def _fact_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return actual in expected if not isinstance(actual, (list, tuple, set)) else all(item in actual for item in expected)
    return actual == expected


def _request_json_values(body: Any, fields: list[str]) -> tuple[Any, ...]:
    try:
        import json
        value = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    except (TypeError, ValueError, UnicodeDecodeError):
        return ()
    return tuple(value.get(field) for field in fields) if isinstance(value, Mapping) else ()


def _rule_matches(condition: Mapping[str, Any], facts: Mapping[str, Any]) -> bool:
    """Match only factual fields; never infer semantics from a URL in code."""
    for key, expected in condition.items():
        if key == "path_prefix":
            path = facts.get("path")
            prefixes = expected if isinstance(expected, list) else [expected]
            if not isinstance(path, str) or not any(
                path.startswith(str(prefix)) for prefix in prefixes
            ):
                return False
        elif key == "request_json":
            try:
                import json
                actual = json.loads((facts.get("_request_body") or b"").decode("utf-8"))
            except (ValueError, UnicodeDecodeError, AttributeError):
                return False
            if not isinstance(actual, Mapping) or any(actual.get(k) != v for k, v in expected.items()):
                return False
        elif key == "response_contains":
            body = facts.get("_response_body") or b""
            values = expected if isinstance(expected, list) else [expected]
            if not all(str(value).encode("utf-8") in body for value in values):
                return False
        elif key == "request_contains":
            body = facts.get("_request_body") or b""
            values = expected if isinstance(expected, list) else [expected]
            if not all(str(value).encode("utf-8") in body for value in values):
                return False
        elif key == "query_contains":
            query_value = facts.get("query", "")
            if isinstance(query_value, Mapping):
                query = " ".join(str(value) for value in query_value.values())
            else:
                query = str(query_value)
            values = expected if isinstance(expected, list) else [expected]
            if not all(str(value).casefold() in query.casefold() for value in values):
                return False
        elif key == "marker_present":
            if bool(facts.get("matched_markers")) != bool(expected):
                return False
        elif key == "marker_source":
            if not facts.get(f"_{expected}_markers"):
                return False
        elif not _fact_matches(facts.get(key), expected):
            return False
    return True


def safe_run_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:100] or "run-adhoc"


def create_app(upstream: str, run_id: str, actor: str, event_sink: EventSink,
               observer: Observer | None = None, timeout: int = 20,
               tls: Mapping[str, Any] | None = None,
               request_scope: Callable[[], AbstractContextManager[Any]] | None = None,
               sequence_allocator: Any = None,
               lifecycle_sink: Callable[[LifecycleEvent], None] | None = None,
               action_registry: ActionBindingRegistry | None = None,
               enforce_policy: bool = False,
               expose_goal_state: bool = False) -> Flask:
    upstream_url = _web_url(upstream)
    if enforce_policy and action_registry is None:
        action_registry = ActionBindingRegistry()
    tls_config = {"mode": "passthrough", "verify": True, **(tls or {})}
    if tls_config["mode"] != "passthrough":
        raise ValueError("only tls.mode=passthrough is currently supported")
    app = Flask(__name__)
    normalizer = observer or WebObserver()

    @app.route("/__ranger_gateway_health__")
    def gateway_health() -> Response:
        return Response("ok", 200, {"Content-Type": "text/plain"})

    @app.route("/", defaults={"path": ""}, methods=HTTP_METHODS)
    @app.route("/<path:path>", methods=HTTP_METHODS)
    def forward_request(path: str) -> Response:
        seq = sequence_allocator.next() if sequence_allocator else -1
        request_started_at = datetime.now(timezone.utc)
        request_path = "/" + path
        query = request.query_string.decode("utf-8", "replace")
        target_path = upstream_url.path.rstrip("/") + request_path
        outbound_path = quote(target_path, safe="/")
        target = urlunsplit((
            upstream_url.scheme,
            upstream_url.netloc,
            outbound_path,
            query,
            "",
        ))
        headers = {key: value for key, value in request.headers if key.lower() != "host"}
        action_id = next(
            (value for key, value in headers.items()
             if key.lower() == "x-ranger-action-id"), None
        )
        step_header = next(
            (value for key, value in headers.items()
             if key.lower() == "x-ranger-step"), None,
        )
        request_id_header = next(
            (value for key, value in headers.items()
             if key.lower() == "x-ranger-request-id"), None,
        )
        headers = {
            key: value for key, value in headers.items()
            if key.lower() not in {"x-ranger-action-id", "x-ranger-step", "x-ranger-request-id"}
        }
        correlation_token = next(
            (value for key, value in request.headers.items()
             if key.lower() == "x-ranger-correlation-token"), None,
        )
        invocation_token = next(
            (value for key, value in request.headers.items()
             if key.lower() == "x-ranger-invocation-token"), None,
        )
        bound_action_id = action_id
        observed_event_id = make_event_id(seq) if seq >= 0 else None
        observed_request_id = request_id_header or (make_request_id(seq) if seq >= 0 else None)
        if action_registry is not None:
            valid_binding = bool(
                action_id and ((correlation_token and action_registry.consume(run_id, action_id, correlation_token)[0])
                or (invocation_token and action_registry.consume_invocation(run_id, action_id, invocation_token)[0]))
            )
            if not action_id:
                active_actions = action_registry.active_actions(run_id)
                if len(active_actions) == 1:
                    bound_action_id = active_actions[0]
                    valid_binding = True
            if not valid_binding:
                if enforce_policy:
                    return Response("invalid action correlation", 403)
                bound_action_id = None
        status = 502
        body = b"upstream unavailable"
        response_headers: list[tuple[str, str]] = [("Content-Type", "text/plain")]
        facts = {
            "scheme": upstream_url.scheme,
            "host": upstream_url.hostname,
            "port": upstream_url.port or (443 if upstream_url.scheme == "https" else 80),
            "method": request.method,
            "path": target_path,
            "destination_host": upstream_url.hostname,
            "destination_port": upstream_url.port or (443 if upstream_url.scheme == "https" else 80),
            "application": "http",
            "resource": target_path,
            "tool_name": None,
            "tool_type": None,
            "query": query,
            "request_size": len(request.get_data()),
            "_request_body": request.get_data(),
            "headers": dict(request.headers),
        }

        try:
            with request_scope() if request_scope is not None else nullcontext():
                response = requests.request(
                    method=request.method,
                    url=target,
                    headers=headers,
                    data=request.get_data(),
                    cookies=request.cookies,
                    allow_redirects=False,
                    timeout=timeout,
                    verify=bool(tls_config["verify"]),
                )
            status = response.status_code
            body = response.content or b""
            response_headers = [
                (key, value) for key, value in response.raw.headers.items()
                if key.lower() not in DROP_RESPONSE_HEADERS
            ]
        except requests.RequestException as error:
            facts["upstream_error"] = type(error).__name__

        facts.update({
            "status": status,
            "response_size": len(body),
            "request_completed_at": datetime.now(timezone.utc).isoformat(),
            "response_content_type": next(
                (value for key, value in response_headers if key.lower() == "content-type"),
                None,
            ),
            "_response_body": body,
        })
        canonical_action = normalize_action({
            "tool": {"name": "http_request", "type": "http_request"},
            "method": request.method, "path": target_path, "url": target,
            "activity": facts.get("activity"),
            "body": facts.get("_request_body"),
            "content_type": request.headers.get("Content-Type"),
        }).to_dict()
        facts.update({
            "action_id": bound_action_id,
            "event_id": observed_event_id,
            "request_id": observed_request_id,
            "step": int(step_header) if str(step_header or "").isdigit() else None,
            "parent_action_id": bound_action_id,
            "correlation_status": "correlated" if bound_action_id else "orphan",
            "raw_tool_name": facts.get("tool_name"),
            "canonical_tool_name": (canonical_action["tool"] or {}).get("name"),
            "canonical_tool_family": (canonical_action["tool"] or {}).get("family"),
            "canonical_intent": canonical_action.get("intent"),
            "normalization_status": canonical_action.get("normalization_status"),
            "canonical_action": canonical_action,
            "action_channel": canonical_action.get("action_channel"),
        })
        try:
            observed_event = normalizer.normalize(
                run_id,
                RawObservation(
                    timestamp=request_started_at, actor=actor, source="gateway",
                    kind="web", action="request", target=target, facts=facts,
                ),
                seq=seq,
            )
            sink_feedback = event_sink(observed_event)
            response_headers = [
                (key, value) for key, value in response_headers
                if key.lower() != OBSERVER_FEEDBACK_HEADER.lower()
            ]
            feedback = _safe_agent_feedback(observed_event)
            if isinstance(sink_feedback, Mapping) and sink_feedback.get("goal_state") == "achieved":
                feedback = f"{feedback};goal_state=achieved" if feedback else "goal_state=achieved"
            if feedback:
                response_headers.append((OBSERVER_FEEDBACK_HEADER, feedback))
            if lifecycle_sink and bound_action_id:
                lifecycle_sink(LifecycleEvent.now(
                    run_id=run_id, seq=seq, action_id=bound_action_id, actor=actor,
                    source="gateway", stage="observed",
                    reference={"event_seq": seq},
                    normalized_action=normalize_action({
                        "tool": {"name": "http_request", "type": "http_request"},
                        "method": request.method, "path": target_path,
                        "url": target, "activity": facts.get("activity"),
                        "operation": facts.get("operation"),
                    }).to_dict(),
                ))
        except Exception:
            raise
        return Response(body, status, response_headers)

    return app


def _web_url(value: str) -> SplitResult:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("upstream must be an absolute http(s) URL")
    parsed.port
    return parsed


HttpObserver = WebObserver


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ranger HTTP/HTTPS gateway observer")
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--run", default="run-adhoc")
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    parser.add_argument("--config", type=Path)
    parser.add_argument(
        "--observer",
        help="optional adapter as module:class (for example environments.juice_shop.observer:JuiceShopObserver)",
    )
    parser.add_argument(
        "--markers", default="",
        help="comma-separated goal markers forwarded to the observer's markers= constructor kwarg "
             "(container mode's gateway runs in its own process/container and cannot receive this "
             "any other way than a CLI flag; host mode instead wires this in-process via load_observer)",
    )
    parser.add_argument("--actor", choices=["agent", "human", "unknown"], default="unknown")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_id = safe_run_id(args.run)
    if args.config:
        import json
        config = RunConfig.from_dict(json.loads(args.config.read_text(encoding="utf-8")))
        if config.run_id != run_id:
            raise ValueError("--run must match config.json run_id")
    else:
        config = RunConfig(
            run_id=run_id, model="unknown", model_version="unknown",
            agent_version="poc", environment="unknown", scenario="adhoc",
            policy="adhoc", max_steps=8, timeout=20,
            started_at=datetime.now(timezone.utc),
        )
    store = RunStore(args.runs_dir, config)
    store.initialize()
    markers = tuple(item.strip() for item in args.markers.split(",") if item.strip())
    options_path = store.run_dir / "observer_options.json"
    if options_path.is_file():
        import json
        observer_options = json.loads(options_path.read_text(encoding="utf-8"))
        if not isinstance(observer_options, dict):
            raise ValueError("observer_options.json must contain an object")
        observer_options.setdefault("markers", markers)
    else:
        observer_options = {"markers": markers}
    observer = _load_observer(args.observer, **observer_options) if args.observer else None
    app = create_app(
        args.upstream, run_id, args.actor, store.append_event,
        observer=observer, timeout=config.timeout, sequence_allocator=SequenceAllocator(),
        lifecycle_sink=store.append_lifecycle,
    )
    print(f"[ranger] run: {run_id}")
    print(f"[ranger] upstream: {args.upstream}")
    print(f"[ranger] events: {store.events_path}")
    app.run(host="0.0.0.0", port=8080, threaded=True)


def load_observer(reference: str, **options: Any) -> Observer:
    module_name, separator, class_name = reference.partition(":")
    if not separator:
        raise ValueError("observer must use module:class format")
    observer_class = getattr(importlib.import_module(module_name), class_name)
    observer = observer_class(**options)
    if not isinstance(observer, Observer):
        raise TypeError(f"{reference} does not implement Observer")
    return observer


_load_observer = load_observer


if __name__ == "__main__":
    main()
