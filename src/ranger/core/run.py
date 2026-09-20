"""Run configuration and filesystem persistence."""

from dataclasses import asdict, dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
from threading import Lock
from typing import Any, Mapping

from .event import Event
from .lifecycle import LifecycleEvent
from .result import RealSystemActivity


class ArtifactPersistenceError(IOError):
    """A required run artifact could not be durably persisted."""


def _atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            directory = path.parent.open("rb")
            try:
                os.fsync(directory.fileno())
            finally:
                directory.close()
        except OSError:
            pass
    finally:
        if temporary.exists():
            temporary.unlink()


@dataclass(frozen=True)
class RunConfig:
    run_id: str
    model: str
    model_version: str
    agent_version: str
    environment: str
    scenario: str
    policy: str
    max_steps: int
    timeout: int
    started_at: datetime
    environment_reset: dict[str, Any] | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    run_token_budget: int | None = None
    seed: int | None = None
    repetition: int | None = None
    provider: str | None = None
    enforcement_enabled: bool = False
    expose_goal_state: bool = False
    agent_runtime: str = "host"
    attacker_container: str | None = None
    network_mode: str = "host"
    gateway_required: bool = False
    control_plane: str | None = None
    model_transport: str | None = None
    roe_semantics_version: str = "2"
    pressure_basis: str | None = None
    pressure_level: str | None = None
    pressure_experiment_id: str | None = None
    command_tools: tuple[str, ...] = ()
    lab_version: str = "v1"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", self.run_id):
            raise ValueError("run_id must be 1-100 safe filename characters")
        if self.started_at.tzinfo is None:
            raise ValueError("started_at must include a timezone")
        if self.max_steps <= 0 or self.timeout <= 0:
            raise ValueError("max_steps and timeout must be positive")
        if self.max_tokens is not None and self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if self.run_token_budget is not None and self.run_token_budget <= 0:
            raise ValueError("run_token_budget must be positive")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["started_at"] = self.started_at.isoformat()
        if self.environment_reset is None:
            data.pop("environment_reset")
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RunConfig":
        values = dict(data)
        values.setdefault("roe_semantics_version", "1")
        started_at = values["started_at"]
        if isinstance(started_at, str):
            values["started_at"] = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        return cls(**values)


class RunStore:
    """Owns the stable runs/<run_id>/ artifact layout."""

    def __init__(self, runs_dir: Path, config: RunConfig):
        self.config = config
        self.run_dir = Path(runs_dir) / config.run_id
        self.config_path = self.run_dir / "config.json"
        self.events_path = self.run_dir / "events.jsonl"
        self.trace_path = self.run_dir / "trace.jsonl"
        self.progress_path = self.run_dir / "progress.jsonl"
        self.lifecycle_path = self.run_dir / "lifecycle.jsonl"
        self.invocations_path = self.run_dir / "invocations.jsonl"
        self.status_path = self.run_dir / "status.json"
        self.result_path = self.run_dir / "result.json"
        self._write_lock = Lock()
        self.persistence_failure: str | None = None

    def initialize(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        if self.config_path.exists():
            existing = RunConfig.from_dict(
                json.loads(self.config_path.read_text(encoding="utf-8"))
            )
            if existing != self.config:
                raise FileExistsError(
                    f"run {self.config.run_id!r} already has a different config"
                )
        else:
            if self.events_path.exists() or self.result_path.exists():
                raise FileExistsError(
                    f"run {self.config.run_id!r} has artifacts without config.json"
                )
            _atomic_json(self.config_path, self.config.to_dict())
        self.events_path.touch(exist_ok=True)
        self.trace_path.touch(exist_ok=True)
        self.lifecycle_path.touch(exist_ok=True)
        self.invocations_path.touch(exist_ok=True)

    def append_event(self, event: Event) -> None:
        if event.run_id != self.config.run_id:
            raise ValueError("event run_id does not match RunConfig")
        line = json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
        try:
            with self._write_lock, self.events_path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            self.persistence_failure = f"evidence_persistence_failure:events:{exc}"
            raise ArtifactPersistenceError(self.persistence_failure) from exc

    def append_trace(self, record: Mapping[str, Any]) -> None:
        """Append one agent-level reasoning step (thought/action/observation).

        This is distinct from ``events.jsonl``: events are Observer-normalized
        facts about what happened, while the trace records what the agent
        thought and decided at each step. Neither judges goal/ROE outcomes.
        """
        line = json.dumps(dict(record), ensure_ascii=False, default=str) + "\n"
        try:
            with self._write_lock, self.trace_path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            # Trace is optional; it must not invalidate an otherwise complete run.
            import warnings
            warnings.warn(f"optional trace persistence failed: {exc}")

    def append_lifecycle(self, event: LifecycleEvent) -> None:
        if event.run_id != self.config.run_id:
            raise ValueError("lifecycle run_id does not match RunConfig")
        line = json.dumps(event.to_dict(), ensure_ascii=False, default=str) + "\n"
        try:
            with self._write_lock, self.lifecycle_path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            self.persistence_failure = f"evidence_persistence_failure:lifecycle:{exc}"
            raise ArtifactPersistenceError(self.persistence_failure) from exc

    def append_invocation(self, record: Mapping[str, Any]) -> None:
        """Persist sanitized parent tool lifecycle records separately from agent trace."""
        line = json.dumps(dict(record), ensure_ascii=False, default=str) + "\n"
        try:
            with self._write_lock, self.invocations_path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            self.persistence_failure = f"evidence_persistence_failure:invocations:{exc}"
            raise ArtifactPersistenceError(self.persistence_failure) from exc

    def sort_events(self) -> None:
        """Order new runs by seq; retain timestamp ordering for legacy runs."""
        with self._write_lock:
            try:
                events = [Event.from_dict(json.loads(line)) for line in
                          self.events_path.read_text(encoding="utf-8").splitlines()
                          if line.strip()]
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self.persistence_failure = f"evidence_persistence_failure:events:{exc}"
                raise ArtifactPersistenceError(self.persistence_failure) from exc
            if events and all(event.seq >= 0 for event in events):
                events.sort(key=lambda event: event.seq)
            elif any(event.seq >= 0 for event in events):
                raise ValueError("mixed legacy and sequenced events")
            else:
                events.sort(key=lambda event: event.timestamp)
            temporary = self.events_path.with_name(f".events.{os.getpid()}.tmp")
            try:
                with temporary.open("w", encoding="utf-8") as stream:
                    stream.write("".join(json.dumps(event.to_dict(), ensure_ascii=False) + "\n" for event in events))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.events_path)
            except OSError as exc:
                self.persistence_failure = f"evidence_persistence_failure:events:{exc}"
                raise ArtifactPersistenceError(self.persistence_failure) from exc
            finally:
                if temporary.exists():
                    temporary.unlink()

    def sort_lifecycle(self) -> None:
        """Canonicalize lifecycle records written by gateway and runner."""
        with self._write_lock:
            try:
                records = [json.loads(line) for line in
                           self.lifecycle_path.read_text(encoding="utf-8").splitlines()
                           if line.strip()]
                completed_tools = {
                    str(json.loads(line).get("action_id"))
                    for line in self.invocations_path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and json.loads(line).get("stage") == "execution_finished"
                    and json.loads(line).get("status") == "completed"
                }
                observed_actions = {str(record.get("action_id")) for record in records
                                    if record.get("stage") == "observed"}
                proposed_actions = {
                    str(record.get("action_id")): record.get("raw_action")
                    for record in records if record.get("stage") == "proposed"
                }
                for record in list(records):
                    if (record.get("stage") == "executed"
                            and isinstance(proposed_actions.get(str(record.get("action_id"))), Mapping)
                            and proposed_actions[str(record.get("action_id"))].get("action") == "run_tool"
                            and str(record.get("action_id")) in completed_tools
                            and str(record.get("action_id")) not in observed_actions):
                        records.append({
                            **record, "stage": "observed", "reference": {"tool_result": True},
                            "source": "runner-reconciliation",
                        })
                action_sequences: dict[str, int] = {}
                for record in records:
                    if record.get("stage") != "observed" and isinstance(record.get("seq"), int):
                        action_id = str(record["action_id"])
                        previous = action_sequences.setdefault(action_id, record["seq"])
                        if previous != record["seq"]:
                            raise ValueError(f"conflicting lifecycle sequence: {action_id}")
                for record in records:
                    if record.get("stage") == "observed":
                        action_id = str(record["action_id"])
                        if action_id in action_sequences:
                            record["seq"] = action_sequences[action_id]
                stage_order = {stage: index for index, stage in enumerate(
                    ("proposed", "policy_decision", "observed", "executed")
                )}
                records.sort(key=lambda record: (
                    record.get("seq", -1),
                    stage_order.get(record.get("stage"), len(stage_order)),
                ))
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self.persistence_failure = f"evidence_persistence_failure:lifecycle:{exc}"
                raise ArtifactPersistenceError(self.persistence_failure) from exc
            temporary = self.lifecycle_path.with_name(f".lifecycle.{os.getpid()}.tmp")
            try:
                with temporary.open("w", encoding="utf-8") as stream:
                    stream.write("".join(json.dumps(record, ensure_ascii=False) + "\n"
                                             for record in records))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.lifecycle_path)
            except OSError as exc:
                self.persistence_failure = f"evidence_persistence_failure:lifecycle:{exc}"
                raise ArtifactPersistenceError(self.persistence_failure) from exc
            finally:
                if temporary.exists():
                    temporary.unlink()

    def write_result(self, result: RealSystemActivity) -> None:
        if result.run_id != self.config.run_id:
            raise ValueError("result run_id does not match RunConfig")
        try:
            _atomic_json(self.result_path, result.to_dict())
        except OSError as exc:
            self.persistence_failure = f"evidence_persistence_failure:result:{exc}"
            raise ArtifactPersistenceError(self.persistence_failure) from exc