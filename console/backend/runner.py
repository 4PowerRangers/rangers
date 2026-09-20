import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from threading import Lock
import time
from uuid import uuid4

import yaml

from .loader import RunLoader
from .models import BatchStatus, RunConfig
from ranger.scenario_paths import resolve_scenario_dir

ALLOWED_COMMAND_TOOLS = ("python3", "curl", "bash", "sh", "nmap")


class RunnerService:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.loader = RunLoader(self.root / "runs")
        self.active_jobs: dict[str, dict] = {}
        self.lock = Lock()
        self.executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ranger-console")

    def start_batch(self, config: RunConfig, *, pressure_basis: str | None = None,
                    pressure_level: str | None = None,
                    pressure_experiment_id: str | None = None) -> str:
        job_id = uuid4().hex[:8]
        pressure_basis = pressure_basis or config.pressure_basis
        pressure_level = pressure_level or config.pressure_level
        pressure_experiment_id = pressure_experiment_id or config.pressure_experiment_id
        runs = []
        for index in range(config.runs_per_worker * config.parallel_workers):
            run_id = f"ui-{config.scenario}-{job_id}-r{index + 1}"
            runs.append({"run_id": run_id, "status": "queued", "process": None})
        with self.lock:
            self.active_jobs[job_id] = {"runs": runs, "stopped": False, "scenario": config.scenario,
                                        "pressure_basis": pressure_basis, "pressure_level": pressure_level,
                                        "pressure_experiment_id": pressure_experiment_id}
        for index, item in enumerate(runs, 1):
            self.executor.submit(self._run_one, job_id, item["run_id"], config, index,
                                 pressure_basis, pressure_level, pressure_experiment_id)
        return job_id

    def start_pressure(self, config: RunConfig) -> dict[str, object]:
        if config.pressure_basis in {"I1", "I2", "A2"}:
            scenario_path = resolve_scenario_dir(self.root / "scenarios", config.scenario) / "scenario.yaml"
            scenario_doc = yaml.safe_load(scenario_path.read_text(encoding="utf-8")) or {}
            profile = ((scenario_doc.get("experiment_dimensions") or {}).get(config.pressure_basis.lower()) or {})
            if not profile.get("supported"):
                raise ValueError(
                    f"{config.pressure_basis} pressure is not configured for {config.scenario}; "
                    "configure the scenario profile before running it."
                )
        experiment_id = f"pressure-{uuid4().hex[:10]}"
        job_ids = [
            self.start_batch(config, pressure_basis=config.pressure_basis,
                             pressure_level=level, pressure_experiment_id=experiment_id)
            for level in ("L0", "L1", "L2", "L3")
        ]
        return {"experiment_id": experiment_id, "job_ids": job_ids,
                "scenario": config.scenario, "pressure_basis": config.pressure_basis,
                "levels": ["L0", "L1", "L2", "L3"]}

    def _run_one(self, job_id: str, run_id: str, config: RunConfig, repetition: int,
                 pressure_basis: str | None = None, pressure_level: str | None = None,
                 pressure_experiment_id: str | None = None):
        with self.lock:
            job = self.active_jobs.get(job_id)
            if not job:
                return
            item = next(x for x in job["runs"] if x["run_id"] == run_id)
            if job["stopped"]:
                item["status"] = "stopped"
                return
            item["status"] = "running"
            item["started_monotonic"] = time.monotonic()
        command = [sys.executable, "-m", "ranger.runner", "run", "--scenario", config.scenario, "--model", config.model,
                   "--run", run_id, "--repetition", str(repetition), "--runs-dir", str(self.root / "runs"), "--scenarios-dir", str(self.root / "scenarios"),
                   "--environments-dir", str(self.root / "environments"), "--progress", "quiet"]
        policy = config.policy
        if not policy:
            default_policy = resolve_scenario_dir(self.root / "scenarios", config.scenario) / "policy.yaml"
            policy = str(default_policy) if default_policy.is_file() else next((str(p) for p in default_policy.parent.glob("*-policy.yaml")), None)
        for flag, value in (("--provider", config.provider), ("--upstream", config.upstream or config.target_url or config.target), ("--policy", policy), ("--max-steps", config.max_steps), ("--max-tokens", config.max_tokens), ("--run-token-budget", config.run_token_budget), ("--temperature", config.temperature), ("--seed", config.seed), ("--timeout", config.timeout)):
            if value not in (None, ""):
                command.extend([flag, str(value)])
        if config.reset_target:
            command.append("--reset-target")
        if config.enforce_policy:
            command.append("--enforce-policy")
        if config.expose_goal_state:
            command.append("--expose-goal-state")
        profile_path = self.root / "runs" / ".command-profiles" / f"{run_id}.yaml"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps({"command_tools": config.command_tools}), encoding="utf-8")
        command.extend(["--command-profile", str(profile_path)])
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.root / "src") + os.pathsep + env.get("PYTHONPATH", "")
        # The runner is host-side, so use the relay's published host port.
        # The Docker service name from .env is only resolvable inside Docker.
        env["RANGER_MODEL_ENDPOINT"] = env.get("RANGER_MODEL_ENDPOINT") or "http://127.0.0.1:8090"
        env["RANGER_LAB_VERSION"] = config.lab_version
        if pressure_basis:
            env["RANGER_PRESSURE_BASIS"] = pressure_basis
        if pressure_level:
            env["RANGER_PRESSURE_LEVEL"] = pressure_level
        if pressure_experiment_id:
            env["RANGER_PRESSURE_EXPERIMENT_ID"] = pressure_experiment_id
        try:
            process = subprocess.Popen(command, cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with self.lock:
                item["process"] = process
                should_stop = item["status"] == "stopping"
            if should_stop:
                self._terminate_process_tree(process)
            stdout, stderr = process.communicate()
            with self.lock:
                was_stopped = item["status"] in {"stopping", "stopped"}
                item["output"] = (stderr or stdout or "").strip()[-4000:]
                item["exit_code"] = process.returncode
            # A zero exit code is not enough to call a run complete.  The
            # runner must have produced a durable artifact directory/result;
            # otherwise the UI would show COMPLETE while every evidence
            # endpoint correctly returns 404 (the subprocess died before it
            # initialized the run).
            run_dir = self.root / "runs" / run_id
            has_artifact = run_dir.is_dir() and (run_dir / "result.json").is_file()
            if was_stopped:
                with self.lock:
                    item["status"] = "stopped"
                self._mark_stopped(run_id)
            elif item["exit_code"] == 0 and has_artifact:
                with self.lock:
                    item["status"] = "completed"
            else:
                with self.lock:
                    item["status"] = "failed"
                    if not item.get("output") and not has_artifact:
                        item["output"] = "runner exited without writing a result artifact"
        except OSError:
            with self.lock:
                item["status"] = "stopped" if item["status"] == "stopping" else "failed"

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            if process.poll() is None:
                process.terminate()
        else:
            process.terminate()

    def _capture_stop(self, item: dict) -> None:
        item["status"] = "stopping"
        started = item.get("started_monotonic")
        if started is not None:
            item["stopped_elapsed_sec"] = max(0.0, time.monotonic() - started)

    def _mark_stopped(self, run_id: str) -> None:
        status_path = self.root / "runs" / run_id / "status.json"
        if not status_path.is_file():
            return
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
            now = datetime.now(timezone.utc).isoformat()
            status.update(state="interrupted", updated_at=now, last_event="run_interrupted")
            status["execution"] = {
                "status": "stopped", "termination_reason": "user_interrupted",
                "valid": None,
            }
            temporary = status_path.with_suffix(".stopped.tmp")
            temporary.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.replace(temporary, status_path)
        except (OSError, ValueError, TypeError):
            return

    def active_job_ids(self) -> list[str]:
        with self.lock:
            return [
                job_id
                for job_id, job in self.active_jobs.items()
                if any(item["status"] not in {"completed", "failed", "stopped"} for item in job["runs"])
            ]

    def status(self, job_id: str) -> BatchStatus:
        with self.lock:
            job = self.active_jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        items = job["runs"]
        live = []
        for item in items:
            current = self.loader.load_live_status(self.root / "runs" / item["run_id"])
            if current:
                summary = self.loader.load_summary(self.root / "runs" / item["run_id"])
                # result.json is the source of truth once the run has
                # initialized. status.json can still say "completed" even
                # when the judge terminated the run as a policy failure.
                current = current.model_copy(update={
                    "scenario": summary.scenario or job["scenario"],
                    "state": summary.status if summary.status in {"completed", "failed", "partial", "invalid", "interrupted"} else current.state,
                    "step": summary.steps,
                    "goal_success": summary.goal_success,
                    "roe_compliant": summary.roe_compliant,
                    "violation_count": summary.violation_count,
                })
            if current:
                if item["status"] in {"stopping", "stopped"}:
                    current = current.model_copy(update={
                        "state": item["status"],
                        "elapsed_sec": item.get("stopped_elapsed_sec", current.elapsed_sec),
                    })
                elif item["status"] == "failed":
                    current = current.model_copy(update={"state": "failed", "error": item.get("output") or "runner exited with an error"})
                live.append(current)
            else:
                live.append({"run_id": item["run_id"], "scenario": job["scenario"], "state": item["status"], "elapsed_sec": item.get("stopped_elapsed_sec"), "error": item.get("output")})
        return BatchStatus(job_id=job_id, total=len(items), running=sum(x["status"] == "running" for x in items), queued=sum(x["status"] == "queued" for x in items),
                           completed=sum(x["status"] in {"completed", "failed", "stopped"} for x in items), runs=live)

    def stop(self, job_id: str):
        processes = []
        with self.lock:
            job = self.active_jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            job["stopped"] = True
            for item in job["runs"]:
                if item.get("process") and item["status"] == "running":
                    self._capture_stop(item)
                    processes.append(item["process"])
                elif item["status"] == "running":
                    self._capture_stop(item)
                elif item["status"] == "queued":
                    item["status"] = "stopped"
        for process in processes:
            self._terminate_process_tree(process)

    def stop_run(self, run_id: str):
        process = None
        with self.lock:
            for job in self.active_jobs.values():
                item = next((x for x in job["runs"] if x["run_id"] == run_id), None)
                if item:
                    if item["status"] == "running":
                        self._capture_stop(item)
                        process = item.get("process")
                    elif item["status"] == "queued":
                        item["status"] = "stopped"
                    break
            else:
                raise KeyError(run_id)
        if process is not None:
            self._terminate_process_tree(process)
        return
