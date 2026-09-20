from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping, Sequence

DEFAULT_ATTACKER_CONTAINER = "ranger-attacker"
CONTAINER_ENV_ALLOWLIST = {
    "RANGER_RUN_ID", "RANGER_SCENARIO_ID", "RANGER_PROVIDER", "RANGER_MODEL",
    "RANGER_MODEL_ENDPOINT",
}


class AgentRuntimeError(RuntimeError):
    """The runtime could not execute the requested process."""


class ContainerNotFoundError(AgentRuntimeError):
    pass


class ContainerStoppedError(AgentRuntimeError):
    pass


class ContainerExecutionError(AgentRuntimeError):
    pass


class AgentProcessError(AgentRuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass(frozen=True)
class ToolExecutionResult:
    status: str
    pid: int | None
    executable: str | None
    process: dict[str, Any]


class HostAgentRuntime:
    name = "host"

    def run(self, function: Callable, *args, **kwargs):
        return function(*args, **kwargs)


class ContainerAgentRuntime:
    name = "container"

    def __init__(self, container: str = DEFAULT_ATTACKER_CONTAINER,
                 *, runner: Callable | None = None):
        self.container = container
        self._runner = runner or subprocess.run

    def _inspect(self, timeout: float) -> str:
        try:
            result = self._runner(
                ["docker", "inspect", "--format", "{{.State.Status}}", self.container],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContainerExecutionError("docker inspect timed out") from exc
        except OSError as exc:
            raise ContainerExecutionError(f"docker unavailable: {exc}") from exc
        if result.returncode != 0:
            raise ContainerNotFoundError(self.container)
        status = result.stdout.strip().lower()
        if status != "running":
            raise ContainerStoppedError(f"{self.container} is {status or 'not running'}")
        return status

    def exec(self, command: Sequence[str], *, env: Mapping[str, str] | None = None,
             timeout: float = 60) -> CommandResult:
        if not command or any(not isinstance(part, str) for part in command):
            raise ValueError("container command must be a non-empty string sequence")
        self._inspect(timeout)
        forwarded = {
            key: str(value) for key, value in (env or {}).items()
            if key in CONTAINER_ENV_ALLOWLIST
        }
        argv = ["docker", "exec"]
        for key, value in forwarded.items():
            argv.extend(["--env", f"{key}={value}"])
        argv.extend([self.container, *command])
        try:
            result = self._runner(
                argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContainerExecutionError("docker exec timed out") from exc
        except OSError as exc:
            raise ContainerExecutionError(f"docker exec failed: {exc}") from exc
        captured = CommandResult(result.stdout, result.stderr, result.returncode)
        if result.returncode != 0:
            if result.returncode == 125:
                raise ContainerExecutionError(
                    f"docker exec failed: {result.stderr.strip()}"
                )
            raise AgentProcessError(
                f"agent process exited {result.returncode}: {result.stderr.strip()}"
            )
        return captured

    def smoke_test(self, *, timeout: float = 30) -> dict[str, CommandResult]:
        return {
            name: self.exec(command, timeout=timeout)
            for name, command in {
                "python": ["python3", "--version"],
                "sqlmap": ["which", "sqlmap"],
                "hashcat": ["which", "hashcat"],
                "john": ["which", "john"],
            }.items()
        }

    def run_tool(self, command: Sequence[str], *, timeout: float = 60,
                 invocation: Any = None, on_invocation: Callable | None = None,
                 policy_gate: Any = None,
                 normalized_action: Mapping[str, Any] | None = None) -> ToolExecutionResult:
        if not command or any(not isinstance(part, str) for part in command):
            raise ValueError("tool command must be a non-empty string sequence")
        policy_decision = {"decision": "allow", "reason": "enforcement_not_enabled"}
        if policy_gate is not None and normalized_action is not None:
            decision = policy_gate.decide(
                invocation.action_id if invocation is not None else "unbound",
                normalized_action,
            )
            policy_decision = decision
            if decision["decision"] == "deny":
                process = {"status": "denied", "pid": None, "executable": None,
                           "execution": False, "policy_decision": decision}
                if invocation is not None:
                    invocation.bind_process(process)
                    if on_invocation:
                        on_invocation(invocation.record("execution_finished", status="denied"))
                return ToolExecutionResult("denied", None, None, process)
        if invocation is not None and on_invocation:
            on_invocation(invocation.record("execution_started"))
        result = self.exec(["python3", "-m", "ranger.agent.tool_runner", "--timeout", str(timeout), *command], timeout=timeout + 5)
        try:
            process = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as exc:
            raise ContainerExecutionError("tool launcher returned malformed metadata") from exc
        process["container"] = self.container
        process["policy_decision"] = policy_decision
        if invocation is not None:
            declared = invocation.tool_name.rsplit("/", 1)[-1].lower()
            resolved = str(process.get("executable") or "").rsplit("/", 1)[-1].lower()
            process["tool_identity_status"] = "match" if declared == resolved else "mismatch"
            invocation.bind_process(process)
            if on_invocation:
                on_invocation(invocation.record("execution_finished", status=process.get("status", "failed")))
        return ToolExecutionResult(
            status=str(process.get("status", "spawn_failed")),
            pid=process.get("pid"), executable=process.get("executable"), process=process,
        )

    @staticmethod
    def environment(values: Mapping[str, str]) -> dict[str, str]:
        """Return only non-secret orchestration metadata for a future agent exec."""
        return {
            key: str(value) for key, value in values.items()
            if key in CONTAINER_ENV_ALLOWLIST
        }

    def run(self, episode_func: Callable, mission: str, gateway_url: str,
            max_steps: int, *, run_dir: str | Path | None = None,
            run_id: str | None = None, timeout: float = 600, **kwargs: Any) -> dict[str, Any]:
        
        if run_dir is None:
            raise AgentRuntimeError("container runtime requires run_dir to exchange episode input/output")
        if run_id is None:
            raise AgentRuntimeError("container runtime requires run_id to locate /app/runs/<run_id>")
        run_dir = Path(run_dir)
        container_run_dir = f"/app/runs/{run_id}"

        gateway_url_value = str(gateway_url)
        model_endpoint = kwargs.get("model_endpoint")
        if not model_endpoint:
            raise AgentRuntimeError(
                "container runtime requires model_endpoint (the model relay's "
                "container-network URL); refusing to let the attacker fall back "
                "to a direct provider call"
            )
        input_payload = {
            "run_id": run_id,
            "scenario": kwargs.get("scenario"),
            "mission": mission,
            "goal": kwargs.get("goal") or {},
            "policy": kwargs["policy"].to_dict() if kwargs.get("policy") is not None else None,
            "max_steps": max_steps,
            "provider": kwargs.get("provider"),
            "model": kwargs.get("model"),
            "temperature": kwargs.get("temperature"),
            "max_tokens": kwargs.get("max_tokens"),
            "run_token_budget": kwargs.get("run_token_budget"),
            "seed": kwargs.get("seed"),
            "gateway_url": gateway_url_value,
            "policy_target": kwargs.get("policy_target"),
            "activity_routes": kwargs.get("activity_routes") or {},
            "runtime": "container",
            "attacker_container": self.container,
            "model_endpoint": model_endpoint,
            "command_profile": kwargs.get("command_profile") or {"command_tools": []},
            "enforce_policy": bool(kwargs.get("enforce_policy", False)),
            "continue_on_policy_deny": bool(kwargs.get("continue_on_policy_deny", True)),
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        input_path = run_dir / "container_input.json"
        outcome_path = run_dir / "container_outcome.json"
        error_path = run_dir / "container_error.txt"
        for stale in (outcome_path, error_path):
            stale.unlink(missing_ok=True)
        input_path.write_text(
            json.dumps(input_payload, ensure_ascii=False, default=str), encoding="utf-8",
        )
        try:
            result = self.exec(
                ["python3", "-B", "-m", "ranger.agent.container_episode",
                 "--run-dir", container_run_dir],
                timeout=timeout,
            )
        except AgentRuntimeError as exc:
            (run_dir / "container_exec_stderr.txt").write_text(str(exc), encoding="utf-8")
            raise AgentRuntimeError(f"container agent episode failed: {exc}") from exc
        (run_dir / "container_exec_stdout.txt").write_text(result.stdout, encoding="utf-8")
        (run_dir / "container_exec_stderr.txt").write_text(result.stderr, encoding="utf-8")
        if not outcome_path.is_file():
            detail = error_path.read_text(encoding="utf-8") if error_path.is_file() else result.stderr
            raise AgentRuntimeError(
                f"container agent episode produced no outcome: {detail.strip()[:2000]}"
            )
        try:
            outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AgentRuntimeError("container agent episode wrote a malformed outcome") from exc
        for name, source, kwarg_name in (
            ("trace", "container_trace.jsonl", "on_step"),
            ("lifecycle", "container_lifecycle.jsonl", "on_lifecycle"),
            ("invocation", "container_invocations.jsonl", "on_invocation"),
        ):
            on_callback = kwargs.get(kwarg_name)
            source_path = run_dir / source
            if on_callback is None or not source_path.is_file():
                continue
            for line in source_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if name == "lifecycle":
                    on_callback(
                        record["stage"], record["action_id"], record["seq"] + 1,
                        record.get("raw_action") or {}, {
                            "decision": record.get("decision"), "reason": record.get("reason"),
                        }, record.get("normalized_action") or {},
                    )
                else:
                    on_callback(record)
        return outcome


def get_agent_runtime(mode: str = "host", *, attacker_container: str = DEFAULT_ATTACKER_CONTAINER):
    if mode == "host":
        return HostAgentRuntime()
    if mode == "container":
        return ContainerAgentRuntime(attacker_container)
    raise ValueError(f"unsupported agent runtime: {mode}")