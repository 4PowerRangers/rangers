"""Measurement-only harness for comparing Capability A/B/C modes."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from statistics import median
from typing import Any, Iterable, Mapping

from .scenario_paths import resolve_scenario_dir


MODES = ("baseline", "v2-a", "v2-a+knowledge", "v2-full")
DEFAULT_SCENARIOS = {
    "1": ("JS-S1-001", "JS-S1-004"),
    "2": ("JS-S2-001", "JS-S2-003", "JS-S2-004"),
    "3": ("JS-S3-001", "JS-S3-004", "H3-IDOR-001"),
    "4": ("JS-S4-001", "JS-S4-007", "JS-S4-010"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def git_commit(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                              capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def difficulty(scenario: str, scenarios_dir: Path) -> str:
    try:
        path = resolve_scenario_dir(scenarios_dir, scenario) / "scenario.yaml"
        import yaml
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError, FileNotFoundError, RuntimeError):
        document = {}
    value = document.get("difficulty") or document.get("difficulty_group")
    if isinstance(value, str):
        match = next((char for char in value if char.isdigit()), None)
        if match:
            return match
    return "unknown"


def select_scenarios(scenarios_dir: Path, requested: Iterable[str] | None = None) -> list[dict[str, str]]:
    names = list(requested) if requested else [item for group in DEFAULT_SCENARIOS.values() for item in group]
    return [{"scenario": name, "difficulty": difficulty(name, scenarios_dir)} for name in names]


def build_matrix(scenarios: list[dict[str, str]], modes: Iterable[str] = MODES,
                 repetitions: int = 5) -> list[dict[str, Any]]:
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    modes = tuple(modes)
    unknown = set(modes) - set(MODES)
    if unknown:
        raise ValueError(f"unsupported capability mode(s): {sorted(unknown)}")
    return [
        {"scenario": item["scenario"], "difficulty": item["difficulty"], "mode": mode,
         "repetition": repetition,
         "run_id": f"capab-{item['scenario']}-{mode.replace('+', '_')}-r{repetition}"}
        for item in scenarios for mode in modes for repetition in range(1, repetitions + 1)
    ]


def experiment_metadata(root: Path, scenarios_dir: Path, scenarios: list[dict[str, str]],
                        *, model: str, provider: str, temperature: float, seed: int,
                        max_steps: int, repetitions: int) -> dict[str, Any]:
    policies = {}
    for item in scenarios:
        policy = resolve_scenario_dir(scenarios_dir, item["scenario"]) / "policy.yaml"
        if policy.is_file():
            policies[item["scenario"]] = sha256(policy)
    knowledge = root / "knowledge" / "web_security.yaml"
    return {
        "schema_version": "capability-ab/1.0",
        "experiment_id": "capability_ab",
        "git_commit": git_commit(root),
        "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "model": model, "provider": provider, "temperature": temperature, "seed": seed,
        "max_steps": max_steps, "repetitions": repetitions, "modes": list(MODES),
        "scenarios": scenarios, "policy_hashes": policies,
        "knowledge_pack_hash": sha256(knowledge) if knowledge.is_file() else None,
        "target_environment": "juice_shop",
        "validity_rule": "provider/environment errors are excluded from success denominator",
    }


def command_for(root: Path, item: Mapping[str, Any], *, model: str, provider: str,
                temperature: float, seed: int, max_steps: int, timeout: int,
                runs_dir: Path, upstream: str | None, scenarios_dir: Path,
                agent_runtime: str = "host") -> list[str]:
    command = [os.environ.get("PYTHON", sys.executable), "-m", "tempera.runner", "run",
               "--scenario", item["scenario"], "--model", model, "--provider", provider,
               "--run", item["run_id"], "--runs-dir", str(runs_dir), "--scenarios-dir", str(scenarios_dir),
               "--repetition", str(item["repetition"]), "--progress", "quiet", "--temperature", str(temperature),
               "--seed", str(seed), "--max-steps", str(max_steps), "--timeout", str(timeout),
               "--agent-runtime", agent_runtime, "--reset-target", "--enforce-policy"]
    if upstream:
        command.extend(("--upstream", upstream))
    return command


def run_matrix(root: Path, rows: list[dict[str, Any]], *, model: str, provider: str,
               temperature: float, seed: int, max_steps: int, timeout: int,
               runs_dir: Path, scenarios_dir: Path, upstream: str | None,
               agent_runtime: str = "host") -> None:
    for row in rows:
        env = os.environ.copy()
        env["TEMPERA_CAPABILITY_MODE"] = row["mode"]
        command = command_for(root, row, model=model, provider=provider, temperature=temperature,
                              seed=seed, max_steps=max_steps, timeout=timeout, runs_dir=runs_dir,
                              upstream=upstream, scenarios_dir=scenarios_dir, agent_runtime=agent_runtime)
        row["command"] = command
        row["returncode"] = subprocess.run(command, cwd=root, env=env, check=False).returncode
        run_dir = runs_dir / row["run_id"]
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "capability_ab.json").write_text(
            json.dumps({"mode": row["mode"], "scenario": row["scenario"],
                        "difficulty": row["difficulty"], "repetition": row["repetition"],
                        "returncode": row["returncode"]}, indent=2), encoding="utf-8",
        )


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
        except json.JSONDecodeError:
            continue
    return records


def _failure_reason(result: Mapping[str, Any], trace: list[Mapping[str, Any]]) -> tuple[str, list[str]]:
    termination = result.get("termination", {}) or {}
    reason = str(termination.get("reason", ""))
    detail = str(termination.get("detail", ""))
    text = f"{reason} {detail}".casefold()
    if "provider" in text or reason in {"provider_error", "model_relay_unavailable"}:
        return "PROVIDER_ERROR", []
    if reason in {"target_error", "runner_error", "evaluator_error", "agent_runtime_error"} or "environment" in text:
        return "ENVIRONMENT_ERROR", []
    if reason == "policy_denied":
        return "POLICY_BLOCKED", []
    if reason in {"max_steps", "token_budget_exhausted"}:
        return "MAX_STEPS_EXHAUSTED", ["INSUFFICIENT_MODEL_REASONING"]
    planners = [record.get("planner", {}) for record in trace if isinstance(record.get("planner"), Mapping)]
    observations = [record.get("observation_summary", {}) for record in trace if record.get("observation_summary")]
    hypotheses = (result.get("capability_v2", {}).get("memory", {}) or {}).get("hypotheses", [])
    knowledge_seen = any(record.get("knowledge_ids") or record.get("knowledge_retrieval", {}).get("selected") for record in planners)
    skills_seen = any(record.get("tool_skill") or record.get("tool_skill", {}).get("id") for record in trace)
    if skills_seen and any(record.get("error") in {"tool_error", "gateway_error"} for record in trace):
        return "TOOL_EXECUTION_FAILURE", []
    if observations and not hypotheses:
        return "PLANNING_FAILURE", []
    if hypotheses and not knowledge_seen:
        return "KNOWLEDGE_ROUTING_FAILURE", []
    if knowledge_seen and skills_seen:
        return "INSUFFICIENT_MODEL_REASONING", []
    return "UNKNOWN", []


def read_run(runs_dir: Path, row: Mapping[str, Any]) -> dict[str, Any]:
    run_dir = runs_dir / str(row["run_id"])
    result_path = run_dir / "result.json"
    if not result_path.is_file():
        return {**row, "present": False, "valid": False, "goal_achieved": False,
                "failure_reason": "ENVIRONMENT_ERROR", "secondary_reasons": []}
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {**row, "present": False, "valid": False, "goal_achieved": False,
                "failure_reason": "ENVIRONMENT_ERROR", "secondary_reasons": []}
    trace = _jsonl(run_dir / "trace.jsonl")
    termination = result.get("termination", {}) or {}
    reason = termination.get("reason")
    validity = result.get("validity", {}) or {}
    provider_error = reason in {"provider_error", "model_relay_unavailable"} or "provider" in str(termination).casefold()
    environment_error = reason in {"target_error", "runner_error", "evaluator_error", "agent_runtime_error"}
    valid = bool(validity.get("valid")) and not provider_error and not environment_error
    hypotheses = (result.get("capability_v2", {}).get("memory", {}) or {}).get("hypotheses", [])
    observed = [record for record in trace if record.get("observation_summary")]
    duplicates = sum(bool((record.get("planner") or {}).get("already_attempted")) for record in trace)
    endpoints = set()
    knowledge_ids = set()
    tool_skills = set()
    for record in trace:
        summary = record.get("observation_summary", {}) or {}
        endpoints.update(summary.get("discovered_endpoints", ()))
        planner = record.get("planner", {}) or {}
        knowledge_ids.update(planner.get("knowledge_ids", ()))
        skill = record.get("tool_skill")
        if isinstance(skill, Mapping):
            skill = skill.get("id")
        if skill:
            tool_skills.add(skill)
    first_hypothesis = next((record.get("step") for record in trace if (record.get("planner") or {}).get("hypothesis_id")), None)
    first_useful = next((record.get("step") for record in observed if (record.get("observation_summary") or {}).get("success_signals") or (record.get("observation_summary") or {}).get("discovered_endpoints")), None)
    failure, secondary = _failure_reason(result, trace) if not result.get("goal", {}).get("success") else (None, [])
    return {**row, "present": True, "valid": valid, "goal_achieved": bool(result.get("goal", {}).get("success")),
            "status": result.get("status"), "termination_reason": reason, "steps_used": termination.get("step") or len(trace),
            "steps_to_first_hypothesis": first_hypothesis, "steps_to_first_useful_observation": first_useful,
            "steps_to_goal": result.get("goal", {}).get("achieved_step"), "duplicate_attempts": duplicates,
            "unique_endpoints_discovered": len(endpoints), "active_hypotheses_created": len(hypotheses),
            "hypotheses_supported": sum(item.get("status") == "supported" for item in hypotheses),
            "hypotheses_rejected": sum(item.get("status") == "rejected" for item in hypotheses),
            "knowledge_entries_retrieved": len(knowledge_ids), "tool_skills_used": len(tool_skills),
            "roe_violations": int((result.get("roe", {}).get("summary", {}) or {}).get("violations", 0) or 0),
            "semantic_gap": result.get("semantic_gap"), "provider_error": provider_error,
            "environment_error": environment_error, "failure_reason": failure,
            "secondary_reasons": secondary, "trace_records": len(trace), "result": result}


def wilson(successes: int, trials: int, z: float = 1.96) -> tuple[float | None, float | None]:
    if not trials:
        return None, None
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def aggregate(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        groups.setdefault((str(row["scenario"]), str(row["mode"])), []).append(row)
    scenario_rows = []
    for (scenario, mode), values in sorted(groups.items()):
        valid = [row for row in values if row.get("valid")]
        successes = sum(bool(row.get("goal_achieved")) for row in valid)
        low, high = wilson(successes, len(valid))
        steps = [row["steps_used"] for row in valid if isinstance(row.get("steps_used"), int)]
        duplicates = sum(int(row.get("duplicate_attempts", 0) or 0) for row in valid)
        attempts = sum(int(row.get("trace_records", 0) or 0) for row in valid)
        scenario_rows.append({"scenario": scenario, "difficulty": values[0].get("difficulty"), "mode": mode,
                              "attempted_runs": len(values), "valid_runs": len(valid), "successes": successes,
                              "success_rate_valid": successes / len(valid) if valid else None,
                              "wilson_low": low, "wilson_high": high, "median_steps": median(steps) if steps else None,
                              "duplicate_rate": duplicates / attempts if attempts else 0.0,
                              "roe_violations": sum(int(row.get("roe_violations", 0) or 0) for row in values),
                              "provider_errors": sum(bool(row.get("provider_error")) for row in values)})
    difficulty_rows = []
    for diff in sorted({row.get("difficulty") for row in scenario_rows}, key=str):
        item = {"difficulty": diff}
        for mode in MODES:
            selected = [row for row in scenario_rows if row["difficulty"] == diff and row["mode"] == mode]
            valid = sum(row["valid_runs"] for row in selected)
            success = sum(row["successes"] for row in selected)
            item[mode] = {"successes": success, "valid_runs": valid,
                          "success_rate_valid": success / valid if valid else None}
        difficulty_rows.append(item)
    overall = {}
    for mode in MODES:
        selected = [row for row in scenario_rows if row["mode"] == mode]
        valid, success = sum(row["valid_runs"] for row in selected), sum(row["successes"] for row in selected)
        overall[mode] = {"successes": success, "valid_runs": valid,
                         "attempted_runs": sum(row["attempted_runs"] for row in selected),
                         "success_rate_valid": success / valid if valid else None}
    def delta(a: str, b: str) -> float | None:
        if overall[a]["success_rate_valid"] is None or overall[b]["success_rate_valid"] is None:
            return None
        return overall[b]["success_rate_valid"] - overall[a]["success_rate_valid"]
    failure_counts: dict[str, int] = {}
    for row in rows:
        if not row.get("goal_achieved"):
            category = str(row.get("failure_reason") or "UNKNOWN")
            failure_counts[category] = failure_counts.get(category, 0) + 1
    failure_total = sum(failure_counts.values())
    failure_labels = {
        "PLANNING_FAILURE": "planning/reasoning", "KNOWLEDGE_ROUTING_FAILURE": "knowledge retrieval",
        "TOOL_EXECUTION_FAILURE": "tool execution", "INSUFFICIENT_MODEL_REASONING": "model raw capability",
        "PROVIDER_ERROR": "provider/environment", "ENVIRONMENT_ERROR": "provider/environment",
        "POLICY_BLOCKED": "policy blocking", "MAX_STEPS_EXHAUSTED": "model raw capability",
        "UNKNOWN": "scenario complexity",
    }
    bottlenecks = {}
    for code, count in failure_counts.items():
        label = failure_labels.get(code, "scenario complexity")
        bottlenecks[label] = bottlenecks.get(label, 0) + count
    return {"overall": overall, "scenario": scenario_rows, "difficulty": difficulty_rows,
            "failure_classification": {
                "counts": failure_counts,
                "rates": {key: value / failure_total for key, value in failure_counts.items()} if failure_total else {},
                "bottlenecks": {key: value / failure_total for key, value in bottlenecks.items()} if failure_total else {},
            },
            "provider_error_rate": sum(bool(row.get("provider_error")) for row in rows) / len(rows) if rows else 0.0,
            "incremental_uplift": {"baseline_to_v2_a": delta("baseline", "v2-a"),
                                   "v2_a_to_knowledge": delta("v2-a", "v2-a+knowledge"),
                                   "knowledge_to_full": delta("v2-a+knowledge", "v2-full"),
                                   "baseline_to_full": delta("baseline", "v2-full")}}


def write_outputs(root: Path, experiment: Mapping[str, Any], rows: list[Mapping[str, Any]], summary: Mapping[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "experiment.json").write_text(json.dumps(experiment, indent=2, ensure_ascii=False), encoding="utf-8")
    (root / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    failures = [row for row in rows if not row.get("goal_achieved")]
    (root / "failures.json").write_text(json.dumps(failures, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    fields = sorted({key for row in summary["scenario"] for key in row})
    with (root / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary["scenario"])