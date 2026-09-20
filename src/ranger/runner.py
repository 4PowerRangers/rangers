"""CLI that owns the run as the minimum experiment unit.

Two subcommands:

``init``  creates ``runs/<run_id>/config.json`` and empty artifact files.
``run``   fully automates a single benchmark run end to end:
          환경 초기화 -> gateway 실행 -> agent 실행 -> event 수집 -> 평가 -> result 저장.
"""

import argparse
import atexit
from collections.abc import Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from threading import Lock
import time
import warnings

import yaml
from dotenv import load_dotenv
from werkzeug.serving import make_server

from .agent import load_agent_adapter, load_mission, run_episode
from .fixtures import apply_fixtures, build_context, infer_condition, resolve_fixtures, safe_fixture_summary
from .agent.runtime import reset_model_usage_log, get_model_usage_summary
from .agent.runtime_control import (
    DEFAULT_ATTACKER_CONTAINER, AgentRuntimeError, get_agent_runtime,
)
from .agent.topology import ForcedGatewayTopology
from .core.environment import EnvironmentAdapter
from .core.bundle import finalize_bundle, validate_run
from .core.lifecycle import LifecycleEvent
from .core.policy import Policy
from .core.result import (
    RealSystemActivity, GoalResult, Metrics, ObserverHealth, ProgressResult,
    Provenance, RoeResult, Termination, Validity,
)
from .core.run import RunConfig, RunStore
from .core.sequence import SequenceService
from .evaluate.pipeline import (
    evaluate_roe_snapshot, evaluate_run, load_events, load_invocations,
)
from .experiment import load_experiment_aggregate, run_ab_experiment
from .observe.database import DatabaseEventCollector
from .observe.gateway import ActionBindingRegistry, create_app, load_observer
from .observe.file_write import build_file_write_contract
from .progress import ProgressReporter
from .scenario_paths import resolve_scenario_dir

SCENARIOS_DIR = Path("scenarios")
ENVIRONMENTS_DIR = Path("environments")
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
_VALID_TERMINATIONS = {
    "agent_done", "max_steps", "action_parse_failed", "unknown_action",
    "container_runtime_smoke", "token_budget_exhausted",
}
_INVALID_REASONS = {
    "provider_error": "experiment_infrastructure_failure",
    "gateway_error": "experiment_infrastructure_failure",
    "target_error": "target_initialization_failure",
    "evaluator_error": "evaluator_failure",
    "runner_error": "experiment_infrastructure_failure",
    "agent_runtime_error": "agent_runtime_failure",
    "user_interrupt": "user_interrupted",
    "policy_denied": "policy_enforcement_denied",
    "environment_reset_invalid": "environment_reset_invalid",
    "provision_invalid": "provision_invalid",
    "evidence_persistence_failure": "evidence_persistence_failure",
    "token_accounting_failed": "token_accounting_failure",
    "adapter_error": "agent_adapter_failure",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _apply_pressure_profile(scenario_doc: dict, policy_doc: dict,
                            pressure_basis: str | None,
                            pressure_level: str | None) -> dict | None:
    """Apply a scenario-declared pressure profile without changing the RoE."""
    basis = str(pressure_basis or "").upper()
    if basis not in {"I1", "I2", "A2"} or pressure_level not in {"L0", "L1", "L2", "L3"}:
        return None
    dimensions = scenario_doc.get("experiment_dimensions") or {}
    profile = dimensions.get(basis.lower()) or {}
    if not profile.get("supported"):
        raise ValueError(f"scenario {scenario_doc.get('scenario_id', 'unknown')} does not support {basis}")
    levels = profile.get("levels") or {}
    condition = levels.get(pressure_level)
    if not isinstance(condition, dict):
        raise ValueError(f"scenario {basis} profile is missing level {pressure_level}")
    instruction = str(condition.get("instruction") or "").strip()
    if instruction:
        existing = policy_doc.get("agent_instructions") or ""
        metadata = []
        if basis == "I1":
            units = profile.get("legal_units") or []
            total_weight = sum(float(unit.get("weight", 0)) for unit in units if isinstance(unit, dict))
            if abs(total_weight - 1.0) > 1e-6:
                raise ValueError("I1 legal unit weights must sum to 1.0")
            coverage = float(condition.get("coverage", -1))
            if not 0.0 <= coverage <= 1.0:
                raise ValueError(f"invalid I1 coverage for {pressure_level}: {coverage}")
            available = condition.get("available_units") or []
            metadata = [f"normalized legal coverage {coverage:.2f}", f"available units: {', '.join(map(str, available)) or 'none'}"]
        elif basis == "I2":
            compliant_steps = int(profile.get("compliant_path_steps", 0))
            shortcut_steps = int(condition.get("shortcut_steps", -1))
            if compliant_steps <= 0 or shortcut_steps < 0:
                raise ValueError(f"invalid I2 step profile for {pressure_level}")
            metadata = [f"compliant path steps: {compliant_steps}", f"prohibited shortcut steps: {shortcut_steps}"]
        policy_doc["agent_instructions"] = (
            f"{existing}\n\n{basis} pressure condition {pressure_level} "
            f"({'; '.join(metadata)}):\n{instruction}"
        ).strip()
    result = {"basis": basis, "level": pressure_level, "instruction": instruction}
    result.update({key: condition[key] for key in ("coverage", "available_units", "shortcut_steps") if key in condition})
    if basis == "I1":
        result["legal_units"] = profile.get("legal_units") or []
    if basis == "I2":
        result["compliant_path_steps"] = int(profile.get("compliant_path_steps", 0))
    return result


def _git_state() -> tuple[str, bool]:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=repo_root,
            check=True, capture_output=True, text=True,
        ).stdout.strip())
        return commit or "unknown", dirty
    except (OSError, subprocess.SubprocessError):
        return "unknown", False


def _image_digests() -> dict[str, str]:
    try:
        listed = subprocess.run(
            ["docker", "ps", "-q"], check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        digests: dict[str, str] = {}
        for container in listed:
            container = container.strip()
            if not container:
                continue
            inspected = subprocess.run(
                ["docker", "inspect", "--format", "{{json .RepoDigests}}", container],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            values = json.loads(inspected or "[]")
            if values:
                digests[container] = str(values[0])
        return digests
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        warnings.warn("Docker 접근 불가: image digests를 수집하지 못했습니다.")
        return {}


def collect_provenance(policy_path: Path, scenario_path: Path, agent_model: str,
                       agent_version: str | None, seed: int | None,
                       started_at: datetime, *, environment_sha256: str = "unknown",
                       environment_version: str | None = None,
                       target_image_digest: str | None = None) -> Provenance:
    try:
        policy_sha256 = sha256_file(policy_path)
    except OSError:
        policy_sha256 = "unknown"
    try:
        scenario_sha256 = sha256_file(scenario_path)
    except OSError:
        scenario_sha256 = "unknown"
    code_commit, code_dirty = _git_state()
    image_digests = _image_digests()
    return Provenance(
        code_commit=code_commit,
        code_dirty=code_dirty,
        policy_sha256=policy_sha256,
        scenario_sha256=scenario_sha256,
        agent_model=agent_model,
        agent_version=agent_version,
        seed=seed,
        image_digests=image_digests,
        started_at=started_at,
        finished_at=started_at,
        image_digests_status="available" if image_digests else "unavailable",
        environment_sha256=environment_sha256,
        environment_version=environment_version,
        target_image_digest=target_image_digest,
    )


def _use_verified_reset_image(provenance: Provenance,
                              environment_reset: dict | None) -> Provenance:
    """Reuse a verified reset image when the early Docker probe missed it."""
    if provenance.image_digests or not environment_reset:
        return provenance
    image_id = environment_reset.get("image_id")
    if not (environment_reset.get("baseline_verified") and
            isinstance(image_id, str) and image_id.startswith("sha256:")):
        return provenance
    image = environment_reset.get("image") or "reset_image"
    return replace(
        provenance,
        image_digests={str(image): image_id},
        image_digests_status="verified_reset_image_id",
    )


def add_init_parser(subparsers: argparse._SubParsersAction) -> None:
    init = subparsers.add_parser("init", help="Create run artifacts only")
    init.add_argument("--run", required=True)
    init.add_argument("--model", required=True)
    init.add_argument("--model-version", default="unknown")
    init.add_argument("--agent-version", default="poc")
    init.add_argument("--environment", required=True)
    init.add_argument("--scenario", required=True)
    init.add_argument("--policy", required=True)
    init.add_argument("--max-steps", required=True, type=int)
    init.add_argument("--timeout", required=True, type=int)
    init.add_argument("--runs-dir", type=Path, default=Path("runs"))


def add_run_parser(subparsers: argparse._SubParsersAction) -> None:
    run = subparsers.add_parser(
        "run", help="Fully automate one run: env init, agent, gateway, events, eval, result"
    )
    run.add_argument("--scenario", required=True, help="Scenario id, e.g. JS-001")
    run.add_argument("--policy", default=None, help="Path to policy YAML file; defaults to scenarios/<scenario>/policy.yaml")
    run.add_argument("--model", required=True, help="Model name passed to the LLM provider")
    run.add_argument("--run", help="Run id; defaults to run-<scenario>-<timestamp>")
    run.add_argument("--model-version", default="unknown")
    run.add_argument("--agent-version", default="poc")
    run.add_argument("--provider", default=None, help="ollama|deepseek; defaults to MODEL_PROVIDER env")
    run.add_argument("--agent", default="internal", choices=("internal", "external:strix"))
    run.add_argument("--agent-runtime", choices=("host", "container"), default="host")
    run.add_argument("--attacker-container", default=DEFAULT_ATTACKER_CONTAINER)
    run.add_argument("--attacker-image", default=None)
    run.add_argument("--command-profile", type=Path, default=None,
                     help="External command capability profile for container agent runs")
    run.add_argument("--external-command", nargs="+", default=None,
                     help="proposal-stream command for --agent external:strix")
    run.add_argument("--temperature", type=float, default=None)
    run.add_argument("--max-tokens", type=int, default=None,
                     help="Maximum completion tokens per LLM call")
    run.add_argument("--run-token-budget", type=int, default=None,
                     help="Maximum cumulative completion tokens for this run")
    run.add_argument("--seed", type=int, default=None)
    run.add_argument("--repetition", type=int, default=None, help="pass@k 반복 인덱스")
    run.add_argument("--upstream", default=None, help="Target base URL; defaults to the environment manifest")
    run.add_argument("--gateway-host", default="127.0.0.1")
    run.add_argument("--gateway-port", type=int, default=0, help="0 picks a free port")
    run.add_argument("--max-steps", type=int, default=None, help="Overrides scenario limits.max_steps")
    run.add_argument("--timeout", type=int, default=None, help="Overrides scenario limits.timeout")
    run.add_argument("--runs-dir", type=Path, default=Path("runs"))
    run.add_argument("--scenarios-dir", type=Path, default=SCENARIOS_DIR)
    run.add_argument("--environments-dir", type=Path, default=ENVIRONMENTS_DIR)
    run.add_argument("--reset-target", action="store_true",
                     help="Recreate and verify the Juice Shop target before this run")
    run.add_argument("--enforce-policy", action="store_true",
                     help="Enable deterministic R2 policy enforcement")
    run.add_argument("--expose-goal-state", action="store_true",
                     help="Expose goal_state=achieved to the agent after observed goal confirmation")
    run.add_argument(
        "--progress", choices=("human", "json", "quiet"), default="human",
        help="Progress console rendering; artifacts are always written",
    )


def add_ab_parser(subparsers: argparse._SubParsersAction) -> None:
    experiment = subparsers.add_parser("ab", help="Compare guardrail OFF and ON")
    for option, kwargs in (
        (("--scenario",), {"required": True}), (("--policy",), {"default": None}),
        (("--model",), {"required": True}), (("--model-version",), {"default": "unknown"}),
        (("--agent-version",), {"default": "poc"}), (("--provider",), {"default": None}),
        (("--temperature",), {"type": float, "default": None}),
        (("--max-tokens",), {"type": int, "default": None}),
        (("--run-token-budget",), {"type": int, "default": None}),
        (("--seed",), {"type": int, "default": None}),
        (("--repetition",), {"type": int, "default": None}),
        (("--upstream",), {"default": None}), (("--gateway-host",), {"default": "127.0.0.1"}),
        (("--gateway-port",), {"type": int, "default": 0}),
        (("--max-steps",), {"type": int, "default": None}),
        (("--timeout",), {"type": int, "default": None}),
        (("--runs-dir",), {"type": Path, "default": Path("runs")}),
        (("--scenarios-dir",), {"type": Path, "default": SCENARIOS_DIR}),
        (("--environments-dir",), {"type": Path, "default": ENVIRONMENTS_DIR}),
    ):
        experiment.add_argument(*option, **kwargs)
    experiment.add_argument("--experiment-id", required=True)
    experiment.add_argument("--experiments-dir", type=Path, default=Path("experiments"))
    experiment.add_argument("--reset-target", action="store_true")
    experiment.add_argument("--enforce-policy", action="store_true")
    experiment.add_argument("--run", default=None)
    experiment.add_argument("--progress", choices=("human", "json", "quiet"), default="human")
    experiment.add_argument("--order-mode", choices=("fixed", "counterbalanced"), default="fixed")


def add_aggregate_parser(subparsers: argparse._SubParsersAction) -> None:
    aggregate = subparsers.add_parser("aggregate-experiments", help="Aggregate experiment summary artifacts")
    aggregate.add_argument("--root", type=Path, required=True)
    aggregate.add_argument("--output", type=Path)


def add_validate_parser(subparsers: argparse._SubParsersAction) -> None:
    validate = subparsers.add_parser("validate-run", help="Validate one run evidence bundle")
    validate.add_argument("--run", required=True)
    validate.add_argument("--runs-dir", type=Path, default=Path("runs"))


def add_ui_parser(subparsers: argparse._SubParsersAction) -> None:
    ui = subparsers.add_parser("ui", help="Open the local run control panel")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=5050)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tempera benchmark runner")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_init_parser(subparsers)
    add_run_parser(subparsers)
    add_ab_parser(subparsers)
    add_aggregate_parser(subparsers)
    add_validate_parser(subparsers)
    add_ui_parser(subparsers)
    return parser.parse_args()


def _default_run_id(scenario: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = secrets.token_hex(2)
    return f"run-{scenario}-{stamp}-{suffix}"


def cmd_init(args: argparse.Namespace) -> None:
    config = RunConfig(
        run_id=args.run, model=args.model, model_version=args.model_version,
        agent_version=args.agent_version, environment=args.environment,
        scenario=args.scenario, policy=args.policy, max_steps=args.max_steps,
        timeout=args.timeout, started_at=datetime.now(timezone.utc),
    )
    store = RunStore(args.runs_dir, config)
    store.initialize()
    print(store.config_path)


def _load_adapter(environment_name: str, environments_dir: Path) -> EnvironmentAdapter:
    """환경 디렉토리의 adapter 모듈에서 어댑터를 로드한다."""
    import importlib

    adapter_ref = f"environments.{environment_name}.adapter"
    if not (environments_dir / environment_name / "adapter.py").is_file():
        raise SystemExit(f"no adapter found in {adapter_ref}")
    try:
        module = importlib.import_module(adapter_ref)
    except ModuleNotFoundError as error:
        if error.name == adapter_ref or adapter_ref.startswith(f"{error.name}."):
            raise SystemExit(f"no adapter found in {adapter_ref}") from error
        raise
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if (isinstance(obj, type) and attr_name.endswith("Adapter")
                and hasattr(obj, "reset") and hasattr(obj, "provision")):
            return obj()
    raise SystemExit(f"no adapter found in {adapter_ref}")


def _with_execution_status(result: RealSystemActivity, outcome: dict) -> RealSystemActivity:
    reason = outcome["reason"]
    if reason.startswith("observer_failed:"):
        return replace(
            result,
            status="invalid",
            termination=Termination(reason, outcome.get("step"), outcome.get("detail")),
            validity=Validity(False, reason),
        )
    if result.validity.reason and result.validity.reason.startswith("observer_failed:"):
        return replace(
            result,
            status="invalid",
            termination=Termination(reason, outcome.get("step"), outcome.get("detail")),
        )
    if result.validity.reason == "no_observed_events" and reason in {
        "policy_denied", "agent_done", "token_budget_exhausted",
    }:
        return replace(
            result,
            status="completed",
            termination=Termination(reason, outcome.get("step"), outcome.get("detail")),
            validity=Validity(True),
        )
    if result.validity.reason == "no_observed_events":
        return replace(
            result,
            termination=Termination(reason, outcome.get("step"), outcome.get("detail")),
        )
    policy_deny_continued = (
        reason == "policy_denied"
        and outcome.get("continue_on_policy_deny", False)
    )
    escaped_violation = bool(
        outcome.get("control_effectiveness", {}).get("escaped_r2_violations", 0)
    )
    valid = reason in _VALID_TERMINATIONS or (policy_deny_continued and not escaped_violation)
    invalid_reason = (
        reason if reason.startswith("observer_failed:")
        else None if valid else outcome.get("validity_reason", _INVALID_REASONS[reason])
    )
    return replace(
        result,
        status=(
            "completed" if valid
            else ("partial" if reason in {"evaluator_error", "user_interrupt"} else "failed")
        ),
        termination=Termination(reason, outcome.get("step"), outcome.get("detail")),
        validity=Validity(valid, invalid_reason),
    )


def _with_execution(result: RealSystemActivity, outcome: dict) -> RealSystemActivity:
    result = _with_execution_status(result, outcome)
    if "control_effectiveness" in outcome:
        result = replace(result, control_effectiveness=outcome["control_effectiveness"])
    if "reproducibility" in outcome:
        result = replace(result, reproducibility=outcome["reproducibility"])
    if "agent_metadata" in outcome:
        result = replace(result, agent_metadata=outcome["agent_metadata"])
    if "usage" in outcome:
        result = replace(result, usage=outcome["usage"])
    return result


def _empty_result(config: RunConfig, outcome: dict,
                  observers: ObserverHealth | None = None,
                  provenance: Provenance | None = None) -> RealSystemActivity:
    return _with_execution(RealSystemActivity(
        run_id=config.run_id,
        goal=GoalResult(False),
        progress=ProgressResult(0),
        roe=RoeResult(False),
        metrics=Metrics(0, 0.0),
        observers=observers or ObserverHealth(),
        provenance=provenance,
    ), outcome)


def _error_outcome(reason: str, error: Exception, step: int | None = None) -> dict:
    return {"reason": reason, "step": step, "detail": f"{type(error).__name__}: {error}"}


@contextmanager
def _hide_sequence_environment():
    hidden = {
        key: os.environ.pop(key)
        for key in ("RANGER_SEQUENCE_TOKEN", "RANGER_SEQUENCE_OBSERVER")
        if key in os.environ
    }
    try:
        yield
    finally:
        os.environ.update(hidden)


def _result_summary(result: RealSystemActivity) -> dict:
    return {
        "status": result.status,
        "termination_reason": result.termination.reason,
        "valid": result.validity.valid,
        "goal_success": result.goal.success,
        "roe_compliant": result.roe.compliant,
    }


def _save_result(store: RunStore, result: RealSystemActivity,
                 reporter: ProgressReporter) -> None:
    if store.persistence_failure and result.validity.valid:
        result = replace(
            result, status="invalid",
            termination=Termination("evidence_persistence_failure", result.termination.step,
                                    store.persistence_failure),
            validity=Validity(False, store.persistence_failure),
        )
    reporter.change_state("saving_result", step=result.termination.step)
    reporter.emit(
        "result_save_started", state="saving_result", step=result.termination.step,
    )
    if result.provenance is not None:
        result = replace(result, provenance=replace(
            result.provenance, finished_at=datetime.now(timezone.utc),
        ))
        if result.provenance.code_dirty or result.provenance.code_commit == "unknown":
            print(
                "WARNING: 재현 불가능한 상태로 실행됨 (uncommitted changes)",
                file=sys.stderr,
            )
    try:
        store.write_result(result)
    except Exception as exc:
        reporter.emit(
            "run_failed", state="failed", step=result.termination.step,
            detail={
                "status": "failed", "termination_reason": "runner_error",
                "valid": False, "error_type": type(exc).__name__,
            },
        )
        raise
    reporter.emit(
        "result_saved", state="saving_result", step=result.termination.step,
        detail={"filename": store.result_path.name},
    )
    final_type, final_state = (
        ("run_completed", "completed") if result.validity.valid
        else (("run_interrupted", "interrupted")
              if result.termination.reason == "user_interrupt"
              else ("run_failed", "failed"))
    )
    reporter.change_state(final_state, step=result.termination.step)
    reporter.emit(
        final_type, state=final_state, step=result.termination.step,
        detail=_result_summary(result),
    )
    finalize_bundle(store.run_dir)


def _save_early_result(runs_dir: Path, config_values: dict, outcome: dict,
                       reporter: ProgressReporter,
                       provenance: Provenance | None = None) -> None:
    config = RunConfig(**config_values, started_at=datetime.now(timezone.utc))
    store = RunStore(runs_dir, config)
    store.initialize()
    _save_result(store, _empty_result(config, outcome, provenance=provenance), reporter)


@contextmanager
def _target_lock():
    # ponytail: one global target lock; split per environment if parallel targets matter.
    path = Path(tempfile.gettempdir()) / "ranger-target.lock"
    lock = path.open("a+b")
    lock.seek(0)
    lock.write(b"\0")
    lock.flush()
    lock.seek(0)
    if os.name == "nt":
        import msvcrt
        while True:
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                time.sleep(0.1)
    else:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        yield
    finally:
        lock.seek(0)
        if os.name == "nt":
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def run_pipeline(args: argparse.Namespace) -> "RunStore":
    with _target_lock():
        return _run_pipeline(args)


def _with_timing_usage(result: RealSystemActivity, args: argparse.Namespace,
                       run_perf_start: float, started_at: datetime,
                       *, override_usage: dict | None = None) -> RealSystemActivity:
    """Attach run duration and DeepSeek token usage to ``result``. Never fails the run.

    ``override_usage`` is used by container mode: LLM calls happen inside
    the attacker container's own Python process (a different process from
    this one), so the Host's in-process ``MODEL_USAGE_LOG`` never sees them
    and ``get_model_usage_summary()`` would report zero calls. Container
    mode instead has ``container_episode.py`` compute its own usage summary
    inside the container and return it as ``outcome["usage"]``; the runner
    passes that dict through here so ``result.json`` reports the real
    token/call counts observed inside the container, not an empty Host-side
    log.
    """
    try:
        ended_at = datetime.now(timezone.utc)
        duration_sec = round(time.perf_counter() - run_perf_start, 6)
        timing = {
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_sec": duration_sec,
        }
        usage = override_usage if override_usage is not None else get_model_usage_summary()
        return replace(
            result, timing=timing,
            usage={**usage, "provider": args.provider, "model": args.model},
        )
    except Exception:
        return result


def _run_pipeline(args: argparse.Namespace) -> "RunStore":
    """Execute one fully automated run and return the RunStore that owns it."""
    run_perf_start = time.perf_counter()
    reset_model_usage_log()
    try:
        scenario_dir = resolve_scenario_dir(args.scenarios_dir, args.scenario)
    except (FileNotFoundError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    scenario_path = scenario_dir / "scenario.yaml"
    policy_path = Path(args.policy) if args.policy else scenario_dir / "policy.yaml"
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    started_at = datetime.now(timezone.utc)
    provenance = collect_provenance(
        policy_path, scenario_path, args.model, args.agent_version, args.seed, started_at,
    )
    scenario_doc = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    policy_doc = yaml.safe_load(policy_path.read_text(encoding="utf-8"))

    # run_id is computed here (rather than further below, where the team's
    # runner previously first needed it) because per-run scenario fixtures
    # (ranger.fixtures) must be resolved from it before anything below
    # reads scenario_doc/policy_doc -- the goal marker, agent_instructions,
    # observer markers, and the Policy object all need the FIXTURE-RESOLVED
    # documents, not the raw YAML.
    run_id = args.run or (
        _default_run_id(args.scenario) if args.repetition is None
        else f"run-{args.scenario}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-r{args.repetition}"
    )

    # Resolve any scenario-declared per-run fixtures (account email,
    # username, review text, filename, ...) exactly once per run, and
    # substitute them everywhere a `{fixture_name}` placeholder appears in
    # the scenario/policy documents. Scenarios with no top-level
    # `fixtures:` block are completely unaffected -- resolve_fixtures/
    # apply_fixtures are no-ops on an absent/empty fixtures mapping, so
    # scenario_doc/policy_doc below are byte-identical to before in that
    # case. This is intentionally generic: no scenario-specific logic here.
    fixture_context = build_context(
        scenario_id=scenario_doc.get("id", args.scenario), run_id=run_id,
        condition=infer_condition(policy_path.stem),
        run_index=args.repetition,
    )
    resolved_fixtures = resolve_fixtures(scenario_doc.get("fixtures"), fixture_context)
    if resolved_fixtures:
        scenario_doc = apply_fixtures(scenario_doc, resolved_fixtures)
        policy_doc = apply_fixtures(policy_doc, resolved_fixtures)

    pressure_basis = os.environ.get("RANGER_PRESSURE_BASIS")
    pressure_level = os.environ.get("RANGER_PRESSURE_LEVEL")
    _apply_pressure_profile(scenario_doc, policy_doc, pressure_basis, pressure_level)

    agent_instructions = policy_doc.get("agent_instructions")
    # I1 and future scenario variants may carry structured goal metadata while
    # retaining the legacy instruction field used by existing agents.
    goal_instruction = ((policy_doc.get("agent") or {}).get("goal") or {}).get("instruction")
    if goal_instruction:
        agent_instructions = f"{agent_instructions}\n\nGoal condition: {goal_instruction}" if agent_instructions else str(goal_instruction)
    policy = Policy.from_dict(policy_doc)
    command_profile = None
    command_profile_path = getattr(args, "command_profile", None)
    if command_profile_path is None:
        # Scenario-local profiles are the safe default for container runs.
        # In particular, JS-S6-001 requires only its declared python3/curl
        # tools; an empty profile makes the goal impossible before the target
        # is even reached.
        default_profile = (
            args.scenarios_dir.parent / "profiles"
            / f"{str(args.scenario).lower().replace('-', '_')}.yaml"
        )
        if default_profile.is_file():
            command_profile_path = default_profile
    if command_profile_path:
        command_profile = yaml.safe_load(Path(command_profile_path).read_text(encoding="utf-8"))

    environment_name = scenario_doc.get("environment")
    if not environment_name:
        raise SystemExit(f"{scenario_path} is missing an 'environment' field")
    environment_path = args.environments_dir / environment_name / "environment.yaml"
    environment_doc = (
        yaml.safe_load(environment_path.read_text(encoding="utf-8"))
        if environment_path.exists() else {}
    )
    try:
        environment_sha256 = sha256_file(environment_path)
    except OSError:
        environment_sha256 = "unknown"
    provenance = replace(
        provenance,
        environment_sha256=environment_sha256,
        environment_version=environment_doc.get("version"),
        target_image_digest=environment_doc.get("target", {}).get("image_digest"),
    )
    # Only fixtures explicitly marked safe_to_record: true are ever written
    # into result.json's provenance (e.g. the resolved account email, for
    # reproducibility); anything unmarked (e.g. a controlled password)
    # defaults closed and never reaches a persisted artifact.
    if resolved_fixtures:
        provenance = replace(provenance, fixtures=safe_fixture_summary(resolved_fixtures))
    upstream = args.upstream or environment_doc.get("target", {}).get("base_url") \
        or environment_doc.get("default_upstream")
    if not upstream:
        raise SystemExit(
            f"no upstream configured: pass --upstream or set target.base_url in {environment_path}"
        )
    target = dict(environment_doc.get("target", {}))
    scenario_target = scenario_doc.get("target", {})
    if isinstance(scenario_target, Mapping) and scenario_target.get("image"):
        target["image"] = scenario_target["image"]
    if target.get("base_url") and upstream != target["base_url"]:
        target.setdefault("runtime_aliases", []).append(upstream)
    observer_ref = environment_doc.get("observer")
    marker = scenario_doc.get("goal", {}).get("marker")
    markers = (marker,) if isinstance(marker, str) else ()
    reporting = scenario_doc.get("reporting", {})
    report_contract = dict(reporting)
    observer_options = {"markers": markers,
                        "classification_rules": scenario_doc.get("observation_rules", []),
                        "ownership_contract": scenario_doc.get("ownership") or {}}
    if reporting:
        observer_options["report_contract"] = report_contract
    file_write_contract = build_file_write_contract(scenario_dir, scenario_doc)
    if file_write_contract:
        observer_options["file_write_contract"] = file_write_contract
    observer = load_observer(observer_ref, **observer_options) if observer_ref else None
    limits = scenario_doc.get("limits", {})
    max_steps = args.max_steps or limits.get("max_steps", 8)
    timeout = args.timeout or limits.get("timeout", 20)
    config_values = dict(
        run_id=run_id, model=args.model, model_version=args.model_version,
        agent_version=args.agent_version, environment=environment_name,
        scenario=args.scenario, policy=policy_path.stem, max_steps=max_steps,
        timeout=timeout,
        temperature=args.temperature, max_tokens=getattr(args, "max_tokens", None),
        run_token_budget=getattr(args, "run_token_budget", None),
        expose_goal_state=bool(getattr(args, "expose_goal_state", False)),
        seed=args.seed, repetition=args.repetition,
        provider=args.provider,
        agent_runtime=getattr(args, "agent_runtime", "host"),
        attacker_container=(
            getattr(args, "attacker_container", DEFAULT_ATTACKER_CONTAINER)
            if getattr(args, "agent_runtime", "host") == "container" else None
        ),
        network_mode=("forced_gateway" if getattr(args, "agent_runtime", "host") == "container" else "host"),
        gateway_required=getattr(args, "agent_runtime", "host") == "container",
        control_plane=("separate" if getattr(args, "agent_runtime", "host") == "container" else None),
        model_transport=("relay" if getattr(args, "agent_runtime", "host") == "container" else None),
        enforcement_enabled=bool(
            getattr(args, "enforce_policy", False)
            or (scenario_doc.get("enforcement", {}) or {}).get("enabled", False)
        ),
        pressure_basis=pressure_basis,
        pressure_level=pressure_level,
        pressure_experiment_id=os.environ.get("RANGER_PRESSURE_EXPERIMENT_ID"),
        command_tools=tuple((command_profile or {}).get("command_tools", ())),
    )
    sequence_service = SequenceService(secrets.token_hex(16), port=0)
    action_registry = ActionBindingRegistry()
    sequence_service.__enter__()
    atexit.register(sequence_service.__exit__, None, None, None)
    os.environ["RANGER_SEQUENCE_TOKEN"] = sequence_service.token
    os.environ["RANGER_SEQUENCE_OBSERVER"] = f"host.docker.internal:{sequence_service.port}"
    reporter = ProgressReporter(
        Path(args.runs_dir) / run_id, run_id, args.scenario, policy_path.stem,
        max_steps, console_mode=getattr(args, "progress", "human"),
    )
    reporter.emit("run_created", state="initializing")
    reporter.emit("run_started", state="initializing")
    environment_reset = None
    if getattr(args, "reset_target", False):
        reporter.change_state("resetting_target")
        reporter.emit("target_reset_started", state="resetting_target")
        try:
            adapter = _load_adapter(environment_name, args.environments_dir)
            # Reset must use the scenario-selected target image.  The generic
            # Juice Shop image does not contain scenario-specific enablement
            # or permissions (notably JS-S6-001's writable proof target).
            try:
                environment_reset = adapter.reset(target_image=target.get("image"))
            except TypeError as exc:
                # Preserve compatibility with third-party adapters that still
                # implement the old no-argument lifecycle contract.
                if "target_image" not in str(exc):
                    raise
                environment_reset = adapter.reset()
        except Exception as exc:
            reporter.emit(
                "target_reset_failed", state="failed",
                detail={"error_type": type(exc).__name__, "error": str(exc)},
            )
            reporter.emit(
                "target_error", state="failed",
                detail={"error_type": type(exc).__name__, "error": str(exc)},
            )
            _save_early_result(
                args.runs_dir, config_values,
                {**_error_outcome("target_error", exc), "validity_reason": "environment_reset_invalid"},
                reporter, provenance,
            )
            raise
        except KeyboardInterrupt:
            _save_early_result(args.runs_dir, config_values, {
                "reason": "user_interrupt", "step": None, "detail": None,
            }, reporter, provenance)
            raise
        provenance = _use_verified_reset_image(provenance, environment_reset)
        reporter.emit(
            "target_reset_completed", state="resetting_target",
            detail={"performed": bool(environment_reset.get("performed", True))},
        )
        reporter.change_state("verifying_target")
        reporter.emit("target_verify_started", state="verifying_target")
        try:
            verifier = getattr(adapter, "verify", None)
            if callable(verifier):
                baseline = verifier()
                environment_reset = {
                    **environment_reset, "baseline_verified": True, "baseline": baseline,
                }
            elif environment_reset.get("baseline_verified") is False:
                raise RuntimeError("target baseline verification failed")
        except Exception as exc:
            reporter.emit(
                "target_verify_failed", state="failed",
                detail={"error_type": type(exc).__name__},
            )
            reporter.emit(
                "target_error", state="failed",
                detail={"error_type": type(exc).__name__},
            )
            _save_early_result(
                args.runs_dir, config_values,
                {**_error_outcome("target_error", exc), "validity_reason": "environment_reset_invalid"},
                reporter, provenance,
            )
            raise
        except KeyboardInterrupt:
            _save_early_result(args.runs_dir, config_values, {
                "reason": "user_interrupt", "step": None, "detail": None,
            }, reporter, provenance)
            raise
        reporter.emit(
            "target_verify_completed", state="verifying_target",
            detail={"verified": bool(environment_reset.get("baseline_verified", True))},
        )
        reporter.change_state("provisioning")
        reporter.emit("scenario_provision_started", state="provisioning")
        try:
            provision = adapter.provision(scenario_doc)
            if not isinstance(provision, dict):
                provision = {"attempted": True, "applied": True, "verified": True}
            if not provision.get("verified", False):
                raise RuntimeError("scenario fixture verification failed")
            environment_reset = {**environment_reset, "provision": provision}
        except Exception as exc:
            reporter.emit(
                "scenario_provision_failed", state="failed",
                detail={"error_type": type(exc).__name__},
            )
            reporter.emit(
                "target_error", state="failed",
                detail={"error_type": type(exc).__name__},
            )
            _save_early_result(
                args.runs_dir, config_values,
                {**_error_outcome("target_error", exc), "validity_reason": "provision_invalid"},
                reporter, provenance,
            )
            raise
        except KeyboardInterrupt:
            _save_early_result(args.runs_dir, config_values, {
                "reason": "user_interrupt", "step": None, "detail": None,
            }, reporter, provenance)
            raise
        reporter.emit("scenario_provision_completed", state="provisioning")

    config = RunConfig(
        **config_values, started_at=started_at,
        environment_reset=environment_reset,
    )
    store = RunStore(args.runs_dir, config)
    store.initialize()
    # The forced gateway runs in a separate container and reads the same
    # scenario-specific observer options as the host observer.
    (store.run_dir / "observer_options.json").write_text(
        json.dumps(observer_options, ensure_ascii=False), encoding="utf-8",
    )

    live_roe_lock = Lock()
    live_roe_active = False
    last_live_roe_payload = None

    def emit_live_roe_snapshot() -> None:
        nonlocal last_live_roe_payload
        if not live_roe_active:
            return
        try:
            observed = load_events(store.events_path)
            if not observed:
                return
            invocations = (
                load_invocations(store.invocations_path)
                if store.invocations_path.is_file() else []
            )
            snapshot = evaluate_roe_snapshot(
                observed, scenario_doc, policy, config,
                environment=environment_doc, invocations=invocations,
            )
            verdicts: dict[str, dict] = {}
            for observed_event in snapshot.events:
                action_id = observed_event.attributes.get("action_id")
                if action_id:
                    verdicts[str(action_id)] = {
                        "action_id": str(action_id),
                        "status": "allowed",
                        "categories": [],
                    }
            for finding in snapshot.roe.violations:
                evidence = finding.get("evidence") or {}
                event_key = finding.get("event_key") or ()
                action_id = (
                    finding.get("action_id") or evidence.get("action_id")
                    or (event_key[2] if len(event_key) > 2 else None)
                )
                if not action_id or str(action_id) not in verdicts:
                    continue
                verdict = verdicts[str(action_id)]
                severity = finding.get("severity", "violation")
                if severity == "violation":
                    verdict["status"] = "escaped"
                elif severity == "unclassified" and verdict["status"] != "escaped":
                    verdict["status"] = "unclassified"
                for category in finding.get("roe_categories") or []:
                    if category not in verdict["categories"]:
                        verdict["categories"].append(category)
            payload = {
                "goal_success": snapshot.goal.success,
                "roe_compliant": snapshot.roe.compliant,
                "verdicts": list(verdicts.values()),
            }
            if payload != last_live_roe_payload:
                last_live_roe_payload = payload
                reporter.emit(
                    "roe_evaluated", state="running_agent", detail=payload,
                )
        except Exception as exc:
            # Live monitoring is supplementary; final evaluation still owns
            # the benchmark result and must not be skipped by a UI update.
            reporter.emit(
                "roe_evaluation_failed", state="running_agent",
                detail={"error_type": type(exc).__name__},
            )

    def append_observed_event(event) -> None:
        """Persist one real observation, then evaluate the observed prefix."""
        with live_roe_lock:
            store.append_event(event)
            emit_live_roe_snapshot()
            if not config.expose_goal_state:
                return None
            observed = load_events(store.events_path)
            snapshot = evaluate_roe_snapshot(
                observed, scenario_doc, policy, config,
                environment=environment_doc,
                invocations=(load_invocations(store.invocations_path)
                             if store.invocations_path.is_file() else []),
            )
            return {"goal_state": "achieved"} if snapshot.goal.success else None

    reporter.change_state("starting_observers")
    database_observation = environment_doc.get("database", {}).get("observation", {})
    observer_health = ObserverHealth(
        gateway="not_started",
        database=("not_started" if database_observation.get("mode") == "sequelize_udp" else "ok"),
    )
    database_collector = None
    token_env = str(database_observation.get("token_env", "RANGER_DB_OBSERVER_TOKEN"))
    database_token = os.environ.get(token_env)
    if database_observation.get("mode") == "sequelize_udp":
        try:
            if not database_token:
                raise ValueError("database observer token is missing")
            database_collector = DatabaseEventCollector(
                run_id, append_observed_event, token=database_token,
                host=str(database_observation.get("bind_host", "127.0.0.1")),
                port=int(database_observation.get("port", 8765)),
            )
            database_collector.start()
        except Exception as exc:
            if database_collector is not None:
                database_collector.close()
                database_collector = None
            observer_health = ObserverHealth(
                gateway="not_started", database="failed",
                detail={"database": type(exc).__name__},
            )
            reporter.emit(
                "database_observer_failed", state="failed",
                detail={"error_type": type(exc).__name__},
            )
        else:
            observer_health = replace(observer_health, database="ok")
            reporter.emit(
                "database_observer_started", state="starting_observers",
                detail={"host": database_collector.address[0], "port": database_collector.address[1]},
            )
    else:
        database_collector = None

    observer_status = {
        "database_observer": "enabled" if database_collector is not None else "disabled",
        "r5_evidence": "available" if database_collector is not None else "unavailable",
        "reason": None if database_collector is not None else "database_observer_not_active",
    }
    observer_health = replace(
        observer_health,
        detail={**observer_health.detail, **observer_status},
    )
    provenance = replace(provenance, observer_status=observer_status)

    requested_port = args.gateway_port or 0
    reporter.change_state("starting_gateway")
    try:
        app = create_app(
            upstream, run_id, actor="agent", event_sink=append_observed_event,
            observer=observer, timeout=timeout, tls=environment_doc.get("tls"),
            request_scope=(database_collector.request_scope if database_collector else None),
            sequence_allocator=sequence_service.allocator,
            lifecycle_sink=store.append_lifecycle,
            action_registry=action_registry,
            enforce_policy=config.enforcement_enabled,
            expose_goal_state=config.expose_goal_state,
        )
        server = make_server(args.gateway_host, requested_port, app)
    except Exception as exc:
        if database_collector is not None:
            database_collector.close()
        reporter.emit(
            "gateway_failed", state="failed", detail={"error_type": type(exc).__name__},
        )
        reporter.emit(
            "gateway_error", state="failed", detail={"error_type": type(exc).__name__},
        )
        result = _empty_result(config, _error_outcome("gateway_error", exc), observer_health, provenance)
        result = _with_timing_usage(result, args, run_perf_start, started_at)
        _save_result(store, result, reporter)
        raise
    actual_port = server.server_address[1]
    observer_health = replace(observer_health, gateway="ok")
    gateway_url = f"http://{args.gateway_host}:{actual_port}"
    # Observed events carry the actual run-local gateway endpoint. Register
    # it dynamically as an alias of the environment's stable target; no
    # environment-specific host or port is assumed here.
    runtime_aliases = target.setdefault("runtime_aliases", [])
    if gateway_url not in runtime_aliases:
        runtime_aliases.append(gateway_url)
    reporter.emit(
        "gateway_started", state="starting_gateway",
        detail={"host": args.gateway_host, "port": actual_port},
    )

    import threading
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    interrupted = False
    with database_collector if database_collector is not None else nullcontext():
        server_thread.start()
        try:
            mission = load_mission(
                scenario_path, gateway=gateway_url, policy_path=policy_path,
                agent_instructions=agent_instructions,
                scenario_document=scenario_doc, policy_document=policy_doc,
            )

            def report(record: dict) -> None:
                store.append_trace({"run_id": run_id, **record})

            def invocation(record: dict) -> None:
                with live_roe_lock:
                    store.append_invocation({"run_id": run_id, **record})
                    emit_live_roe_snapshot()

            def lifecycle(stage: str, action_id: str, step: int,
                          raw_action: dict, details: dict | None,
                          normalized_action: dict) -> None:
                details = details or {}
                store.append_lifecycle(LifecycleEvent.now(
                    run_id=run_id, seq=step - 1, action_id=action_id,
                    actor="agent", source="runner", stage=stage,
                    raw_action=raw_action if stage == "proposed" else None,
                    reference=None if stage == "proposed" else {"action_step": step},
                    normalized_action=normalized_action,
                    decision=details.get("decision"), reason=details.get("reason"),
                ))

            def progress(event_type: str, step: int, detail: dict) -> None:
                reporter.emit(event_type, state="running_agent", step=step, detail=detail)

            outcome = {"reason": "runner_error", "step": None, "detail": None}
            try:
                reporter.change_state("running_agent")
                reporter.emit("agent_started", state="running_agent")
                live_roe_active = True
                selected_adapter = load_agent_adapter(
                    getattr(args, "agent", "internal"),
                    command=getattr(args, "external_command", None),
                    agent_version=args.agent_version,
                    provider=args.provider,
                    model=args.model,
                )
                runtime = get_agent_runtime(
                    config.agent_runtime,
                    attacker_container=config.attacker_container or DEFAULT_ATTACKER_CONTAINER,
                )
                if config.agent_runtime == "container":
                    gateway_name = f"ranger-gateway-{hashlib.sha256(run_id.encode()).hexdigest()[:12]}"
                    topology = ForcedGatewayTopology(
                        attacker=config.attacker_container or DEFAULT_ATTACKER_CONTAINER,
                        gateway=gateway_name,
                        target=target.get("container", "ranger-juice-forced"),
                        target_image=target.get("image", "ranger-juice-shop:latest"),
                        attacker_image=(getattr(args, "attacker_image", None)
                                        or os.environ.get("RANGER_ATTACKER_IMAGE")
                                        or "ranger-attacker:kali"),
                        target_port=int(target.get("port", 3000)),
                        run_dir=store.run_dir,
                        model_relay=os.environ.get("RANGER_MODEL_RELAY_CONTAINER", "ranger-model-relay"),
                        model_relay_provider=args.provider,
                        model_relay_model=args.model,
                        model_relay_upstream=os.environ.get("RANGER_MODEL_UPSTREAM"),
                        model_relay_allowed_endpoints={item.strip() for item in os.environ.get(
                            "RANGER_MODEL_ALLOWED_ENDPOINTS", "").split(",") if item.strip()},
                    )
                    try:
                        # No os.environ["RANGER_PROVIDER"/"RANGER_MODEL"]
                        # writes here: ForcedGatewayTopology and the model
                        # relay container only ever consume the explicit
                        # model_relay_provider/model_relay_model kwargs
                        # passed above, and nothing in this runner reads
                        # those env vars back. Writing them into the Host
                        # process's own environment was dead code left over
                        # from a prior design, and it is exactly the
                        # "ambient Host env" pattern that caused the
                        # fail-closed masking bugs fixed previously
                        # (topology._model_relay_config()'s removed
                        # os.environ fallback) -- keeping it around risked
                        # silently reviving that fallback if ever
                        # reintroduced. runner must only pass config
                        # explicitly to topology/runtime, never leave it in
                        # os.environ for a lower layer to rediscover.
                        topology.ensure(run_id, observer_ref=observer_ref, markers=markers)
                        topology.validate_current_arm(run_id)
                        # The forced-gateway topology's physical target
                        # container (default "ranger-juice-forced") is an
                        # internal orchestration detail distinct from the
                        # stable target identity scenarios/policies declare
                        # (environment.yaml's target.base_url, e.g.
                        # "http://ranger-juice:3000"). Without registering
                        # it as a runtime alias here, evaluate_run's
                        # normalize_targets() never rewrites
                        # "http://ranger-juice-forced:3000/..." event
                        # targets back to the declared identity, so every
                        # single container-mode event fails R1
                        # target_authorization as "not_allowed" even when
                        # the agent only ever hit the one authorized path --
                        # verified live: this was silently masked before
                        # because container mode never got past the smoke
                        # stage to observe a real agent event.
                        container_target_alias = f"http://{topology.topology.target}:{topology.target_port}"
                        if container_target_alias not in target.get("runtime_aliases", []):
                            target.setdefault("runtime_aliases", []).append(container_target_alias)
                        smoke = runtime.smoke_test()
                        gateway_smoke = topology.smoke(runtime)
                        isolation = topology.isolation_report(runtime)
                        reporter.emit(
                            "heartbeat", state="running_agent",
                            detail={
                                name: (result.stdout or result.stderr).strip()
                                for name, result in smoke.items()
                            } | {"gateway": gateway_smoke, "isolation": isolation},
                        )
                        # container_gateway_url is the gateway's Docker network
                        # DNS name, never a Host loopback/published port: this
                        # is what the attacker container's own DNS resolves,
                        # and topology.ensure()/validate() already guarantee
                        # the attacker cannot resolve or route to the target
                        # directly, only to the gateway container.
                        container_gateway_url = f"http://{gateway_name}:8080"
                        model_endpoint = f"http://{topology.model_relay}:8090"
                        # The mission text built above embeds the Host-facing
                        # gateway_url (127.0.0.1:<port>) for display in the
                        # prompt; do_http() always routes through the
                        # ``gateway`` parameter passed to run_episode (never
                        # by parsing mission text), so this rebuild is a
                        # correctness/no-leakage fix for what the agent is
                        # TOLD its gateway is, not a functional requirement
                        # for where requests actually go.
                        container_mission = load_mission(
                            scenario_path, gateway=container_gateway_url,
                            policy_path=policy_path, agent_instructions=agent_instructions,
                            scenario_document=scenario_doc, policy_document=policy_doc,
                        )
                        with _hide_sequence_environment():
                            outcome = runtime.run(
                                run_episode,
                                container_mission, container_gateway_url, max_steps,
                                provider=args.provider, model=args.model,
                                temperature=args.temperature, on_step=report,
                                max_tokens=getattr(args, "max_tokens", None),
                                run_token_budget=config.run_token_budget,
                                on_progress=progress, on_lifecycle=lifecycle,
                                policy=policy,
                                enforce_policy=config.enforcement_enabled,
                                continue_on_policy_deny=True,
                                policy_target=upstream,
                                activity_routes=scenario_doc.get("activity_routes", {}),
                                seed=config.seed,
                                run_id=run_id,
                                action_registry=action_registry,
                                scenario=args.scenario,
                                goal=scenario_doc.get("goal", {}),
                                adapter=selected_adapter,
                                on_invocation=invocation,
                                runtime=config.agent_runtime,
                                run_dir=store.run_dir,
                                model_endpoint=model_endpoint,
                                command_profile=command_profile,
                            )
                    finally:
                        topology.cleanup()
                else:
                    with _hide_sequence_environment():
                        outcome = runtime.run(
                            run_episode,
                            mission, gateway_url, max_steps,
                            provider=args.provider, model=args.model,
                            temperature=args.temperature, on_step=report,
                            max_tokens=getattr(args, "max_tokens", None),
                            run_token_budget=config.run_token_budget,
                            on_progress=progress, on_lifecycle=lifecycle,
                            policy=policy,
                            enforce_policy=config.enforcement_enabled,
                            continue_on_policy_deny=True,
                            policy_target=upstream,
                            activity_routes=scenario_doc.get("activity_routes", {}),
                            seed=config.seed,
                            run_id=run_id,
                            action_registry=action_registry,
                            scenario=args.scenario,
                            goal=scenario_doc.get("goal", {}),
                            adapter=selected_adapter,
                            on_invocation=invocation,
                            runtime=config.agent_runtime,
                            model_endpoint=getattr(args, "model_endpoint", None),
                            cancel_event=getattr(args, "cancel_event", None),
                        )
            except KeyboardInterrupt:
                interrupted = True
                outcome = {"reason": "user_interrupt", "step": None, "detail": None}
            except Exception as exc:
                outcome = _error_outcome(
                    "agent_runtime_error" if isinstance(exc, AgentRuntimeError) else "runner_error",
                    exc,
                )
        finally:
            live_roe_active = False
            server.shutdown()
            server_thread.join(timeout=5)

    if interrupted:
        result = _empty_result(config, outcome, provenance=provenance)
        result = _with_timing_usage(result, args, run_perf_start, started_at)
        _save_result(store, result, reporter)
        raise KeyboardInterrupt

    reporter.change_state("evaluating", step=outcome.get("step"))
    reporter.emit(
        "evaluation_started", state="evaluating", step=outcome.get("step"),
    )
    try:
        store.sort_lifecycle()
        store.sort_events()
        result = _with_execution(
            evaluate_run(
                store.events_path, scenario_doc, policy, config,
                environment=environment_doc,
                observers=observer_health,
                lifecycle_path=store.lifecycle_path,
            ),
            outcome,
        )
        result = replace(result, provenance=provenance)
        reporter.emit(
            "evaluation_completed", state="evaluating", step=outcome.get("step"),
            detail={
                "current_stage": result.progress.current_stage,
                "goal_success": result.goal.success,
                "roe_compliant": result.roe.compliant,
            },
        )
    except KeyboardInterrupt:
        result = _empty_result(config, {
            "reason": "user_interrupt", "step": outcome.get("step"), "detail": None,
        }, provenance=provenance)
        result = _with_timing_usage(result, args, run_perf_start, started_at)
        _save_result(store, result, reporter)
        raise
    except Exception as exc:
        reporter.emit(
            "evaluation_failed", state="failed", step=outcome.get("step"),
            detail={"error_type": type(exc).__name__},
        )
        result = _empty_result(config, _error_outcome("evaluator_error", exc), provenance=provenance)
        result = _with_timing_usage(result, args, run_perf_start, started_at)
        _save_result(store, result, reporter)
        raise
    result = _with_timing_usage(
        result, args, run_perf_start, started_at,
        override_usage=outcome.get("usage"),
    )
    _save_result(store, result, reporter)
    sequence_service.__exit__(None, None, None)
    if outcome.get("detail"):
        error_path = store.run_dir / "episode_error.txt"
        error_path.write_text(outcome["detail"], encoding="utf-8")
    return store


def cmd_run(args: argparse.Namespace) -> None:
    run_pipeline(args)


def cmd_ab(args: argparse.Namespace) -> None:
    print(json.dumps(run_ab_experiment(args, run_pipeline), indent=2, ensure_ascii=False))


def cmd_aggregate(args: argparse.Namespace) -> None:
    summary, errors = load_experiment_aggregate(args.root)
    output = args.output or args.root / "aggregate-summary.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    from .core.run import _atomic_json
    _atomic_json(output, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if errors:
        raise SystemExit(1)


def cmd_validate(args: argparse.Namespace) -> None:
    report = validate_run(args.runs_dir / args.run)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report["valid"]:
        raise SystemExit(1)


def cmd_ui(args: argparse.Namespace) -> None:
    from .control_panel import serve
    serve(Path.cwd(), args.host, args.port)


def main() -> None:
    load_dotenv(ENV_PATH, override=False)
    args = parse_args()
    if args.command == "init":
        cmd_init(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "ab":
        cmd_ab(args)
    elif args.command == "aggregate-experiments":
        cmd_aggregate(args)
    elif args.command == "validate-run":
        cmd_validate(args)
    elif args.command == "ui":
        cmd_ui(args)


if __name__ == "__main__":
    main()
