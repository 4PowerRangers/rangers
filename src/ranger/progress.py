"""Durable orchestration progress history and latest-state snapshot."""

from datetime import datetime, timezone
import json
import os
import time
from pathlib import Path
import re
import sys
from threading import Lock, get_ident
from typing import Any, Mapping, TextIO
from urllib.parse import parse_qsl, urlsplit


RUN_STATES = {
    "initializing", "resetting_target", "verifying_target", "provisioning",
    "starting_observers", "starting_gateway", "running_agent", "evaluating",
    "saving_result", "completed", "failed", "interrupted",
}

EVENT_TYPES = {
    "run_created", "run_started", "state_changed",
    "target_reset_started", "target_reset_completed", "target_reset_failed",
    "target_verify_started", "target_verify_completed", "target_verify_failed",
    "scenario_provision_started", "scenario_provision_completed",
    "scenario_provision_failed", "database_observer_started",
    "database_observer_failed", "gateway_started", "gateway_failed",
    "agent_started", "agent_step_started", "agent_action_parsed",
    "agent_action_completed", "agent_action_failed", "agent_step_completed",
    "agent_done", "action_parse_failed", "policy_denied", "unknown_action", "max_steps_reached",
    "provider_error", "adapter_error", "gateway_error", "target_error", "evaluation_started",
    "evaluation_completed", "evaluation_failed", "result_save_started",
    "roe_evaluated", "roe_evaluation_failed",
    "result_saved", "run_interrupted", "run_completed", "run_failed", "heartbeat",
}
# ponytail: heartbeat is producer-driven; add a scheduler only for measured long silent waits.

_SENSITIVE_KEYS = re.compile(
    r"authorization|cookie|password|token|api.?key|secret|body|jwt|sql|marker",
    re.IGNORECASE,
)
_SENSITIVE_VALUES = (
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b"),
    re.compile(r"\b(?:sk|RANGER)-(?:[A-Za-z0-9_-]+)\b", re.IGNORECASE),
)


def read_progress(path: Path) -> list[dict[str, Any]]:
    """Read complete JSONL events, ignoring a malformed trailing write."""
    events = []
    if not Path(path).is_file():
        return events
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


class ProgressReporter:
    """Append progress events and atomically maintain status.json."""

    def __init__(self, run_dir: Path, run_id: str, scenario: str, policy: str,
                 max_steps: int, console_mode: str = "human",
                 stream: TextIO | None = None) -> None:
        if console_mode not in {"human", "json", "quiet"}:
            raise ValueError("console_mode must be human, json, or quiet")
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.console_mode = console_mode
        self.stream = stream or sys.stdout
        self.progress_path = self.run_dir / "progress.jsonl"
        self.status_path = self.run_dir / "status.json"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.progress_path.touch(exist_ok=True)
        if self.progress_path.stat().st_size:
            with self.progress_path.open("rb+") as stream:
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b"\n":
                    stream.seek(0, os.SEEK_END)
                    stream.write(b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
        history = read_progress(self.progress_path)
        self._seq = max((event.get("seq", 0) for event in history), default=0)
        self._lock = Lock()
        started_at = (
            history[0].get("ts") if history
            else datetime.now(timezone.utc).isoformat()
        )
        self._status = {
            "run_id": run_id,
            "scenario": scenario,
            "policy": policy,
            "state": "initializing",
            "step": None,
            "last_event": None,
            "updated_at": started_at,
            "started_at": started_at,
            "execution": {"status": "running", "termination_reason": None, "valid": None},
            "agent": {"current_step": None, "max_steps": max_steps, "last_action": None},
            "progress": {
                "current_stage": None,
                "goal_observed": False,
                "roe_violation_observed": False,
            },
        }
        for event in history:
            self._update_status(event)

    def emit(self, event_type: str, *, state: str, step: int | None = None,
             detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown progress event type: {event_type}")
        if state not in RUN_STATES:
            raise ValueError(f"unknown run state: {state}")
        with self._lock:
            self._seq += 1
            event = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "run_id": self.run_id,
                "type": event_type,
                "state": state,
                "step": step,
                "detail": _sanitize_detail(detail or {}),
            }
            line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
            with self.progress_path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            self._update_status(event)
            self._write_status()
            self._render(event)
            return event

    def change_state(self, state: str, *, step: int | None = None) -> dict[str, Any]:
        return self.emit("state_changed", state=state, step=step)

    def _update_status(self, event: Mapping[str, Any]) -> None:
        detail = event["detail"]
        self._status.update(
            state=event["state"], step=event["step"],
            last_event=event["type"], updated_at=event["ts"],
        )
        if event["step"] is not None:
            self._status["agent"]["current_step"] = event["step"]
        if event["type"] in {"agent_action_parsed", "agent_action_completed"}:
            self._status["agent"]["last_action"] = {
                key: detail[key] for key in ("action", "method", "path", "query_keys", "status_code")
                if key in detail
            }
        if event["type"] == "evaluation_completed":
            self._status["progress"].update(
                current_stage=detail.get("current_stage"),
                goal_observed=bool(detail.get("goal_success")),
                roe_violation_observed=not bool(detail.get("roe_compliant", True)),
            )
        if event["type"] == "roe_evaluated":
            self._status["progress"].update(
                goal_observed=(
                    self._status["progress"]["goal_observed"]
                    or bool(detail.get("goal_success"))
                ),
                roe_violation_observed=(
                    self._status["progress"]["roe_violation_observed"]
                    or not bool(detail.get("roe_compliant", True))
                ),
            )
        if event["type"] in {"run_completed", "run_failed", "run_interrupted"}:
            self._status["execution"] = {
                "status": detail.get("status"),
                "termination_reason": detail.get("termination_reason"),
                "valid": detail.get("valid"),
            }

    def _write_status(self) -> None:
        temporary = self.run_dir / f".status.{os.getpid()}.{get_ident()}.tmp"
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(self._status, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            for attempt in range(5):
                try:
                    os.replace(temporary, self.status_path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.02)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _render(self, event: Mapping[str, Any]) -> None:
        if self.console_mode == "quiet":
            return
        if self.console_mode == "json":
            print(json.dumps(event, ensure_ascii=False), file=self.stream, flush=True)
            return
        detail = event["detail"]
        event_type = event["type"]
        if event_type == "state_changed":
            message = f"[runner] state: {event['state']}"
        elif event_type == "target_reset_completed":
            message = "[runner] reset: completed"
        elif event_type == "target_verify_completed":
            message = "[runner] target verify: completed"
        elif event_type == "scenario_provision_completed":
            message = "[runner] provision: completed"
        elif event_type == "database_observer_started":
            message = "[runner] database observer: started"
        elif event_type == "gateway_started":
            message = f"[runner] gateway: started on port {detail.get('port')}"
        elif event_type == "agent_action_completed":
            message = (
                f"[agent] step {event['step']}: {detail.get('method')} "
                f"{detail.get('path')} -> {detail.get('status_code')}"
            )
        elif event_type in {"run_completed", "run_failed", "run_interrupted"}:
            message = (
                f"[runner] status: {detail.get('status')}\n"
                f"[runner] termination: {detail.get('termination_reason')}\n"
                f"[runner] validity: {'valid' if detail.get('valid') else 'invalid'}"
            )
        elif event_type == "result_saved":
            message = "[runner] result: saved"
        elif event_type.endswith("_failed") or event_type in {
            "provider_error", "adapter_error", "gateway_error", "target_error", "action_parse_failed",
            "unknown_action", "max_steps_reached", "agent_done",
        }:
            message = f"[runner] {event_type}"
        else:
            return
        print(message, file=self.stream, flush=True)


def _sanitize_detail(detail: Mapping[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in detail.items():
        name = str(key)
        if _SENSITIVE_KEYS.search(name):
            continue
        if name in {"path", "url", "target"} and isinstance(value, str):
            parsed = urlsplit(value)
            clean["path" if name != "target" else name] = parsed.path or "/"
            query_keys = sorted({item[0] for item in parse_qsl(parsed.query, keep_blank_values=True)})
            if query_keys:
                clean["query_keys"] = query_keys
            continue
        clean[name] = _sanitize_value(value)
    return clean


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _sanitize_detail(value)
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        for pattern in _SENSITIVE_VALUES:
            value = pattern.sub("[REDACTED]", value)
    return value
