#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import requests
from dotenv import load_dotenv
from typing import Any

from ranger.core.bundle import validate_run
from ranger.agent.topology import ForcedGatewayTopology, TopologyError

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = ROOT / "environments" / "environment-v1"
ARTIFACTS = ROOT / "artifacts" / "environment-v1"
DESIGN = ENVIRONMENT / "design.json"
SCENARIOS = ENVIRONMENT / "scenarios"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_design() -> dict[str, Any]:
    return json.loads(DESIGN.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def arm_order(pair_id: str) -> list[str]:
    digest = int(hashlib.sha256(pair_id.encode()).hexdigest(), 16)
    return ["guardrail_off", "guardrail_on"] if digest % 2 else ["guardrail_on", "guardrail_off"]


def matrix(design: dict[str, Any], models: dict[str, dict[str, Any]] | None = None,
           *, single_model: bool = False) -> list[dict[str, Any]]:
    rows = []
    models = models or {}
    agents = design["design"]["agent_conditions"][:1] if single_model else design["design"]["agent_conditions"]
    for base_agent in agents:
        agent = {**base_agent, **models.get(base_agent["id"], {})}
        for scenario in design["scenarios"]:
            if scenario["id"] not in design["design"]["pilot_scenario_ids"]:
                continue
            for repeat in range(1, design["design"]["repeats"] + 1):
                pair_id = f"{agent['id']}__{scenario['id']}__r{repeat}"
                rows.append({"pair_id": pair_id, "agent": agent, "scenario": scenario,
                             "runtime": design["design"]["runtime"],
                             "repeat": repeat, "execution_order": arm_order(pair_id),
                             "arms": [{"arm": arm, "run_id": f"{pair_id}__{arm}",
                                       "guardrail": arm.removeprefix("guardrail_")}
                                      for arm in ("guardrail_off", "guardrail_on")]})
    return rows


def _hashes(row: dict[str, Any]) -> dict[str, str]:
    scenario = SCENARIOS / row["scenario"]["id"]
    environment = ROOT / "environments" / "juice_shop" / "environment.yaml"
    return {"prompt_hash": sha256(scenario / "prompt.txt"), "policy_hash": sha256(scenario / "policy.yaml"),
            "scenario_hash": sha256(scenario / "scenario.yaml"), "environment_hash": sha256(environment)}


def fairness_check(row: dict[str, Any]) -> tuple[bool, list[str]]:
    agent = row["agent"]
    common = {**_hashes(row), "model_id": agent.get("model_id", agent.get("model")),
              "provider": agent.get("provider"), "model_version": agent.get("model_version", "unspecified"),
              "endpoint_config_identity": agent.get("endpoint_config_identity", "configured"),
              "temperature": row["runtime"]["temperature"], "max_steps": row["runtime"]["max_steps"],
              "timeout": row["runtime"]["timeout"],
              "seed_requested": agent.get("seed_requested"), "seed_applied": agent.get("seed_applied"),
              "adapter": agent.get("adapter"), "adapter_version": agent.get("adapter_version", "environment-v1"),
              "reset_requirements": "reset_and_provision_before_each_arm"}
    arms = [{**common, **{key: arm[key] for key in common if key in arm}, "enforcement": arm["guardrail"]}
            for arm in row["arms"]]
    errors = [f"{key} differs across OFF/ON" for key in common if arms[0][key] != arms[1][key]]
    return not errors, errors


def preflight(design: dict[str, Any], rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    errors: list[str] = []
    single_model = bool(args.single_model)
    stage11 = (getattr(args, "repetitions", None) is not None or getattr(args, "scenario_ids", None) or
              getattr(args, "seed_strategy", "unsupported") != "unsupported" or getattr(args, "base_seed", None) is not None)
    expected_runs = len(rows) * 2 if stage11 else (12 if single_model else design["design"]["planned_runs"])
    if len(rows) * 2 != expected_runs:
        errors.append("design matrix count does not match planned_runs")
    if "C-activity-operation-boundary" in design["design"]["pilot_scenario_ids"]:
        errors.append("scenario C is deferred from pilot v1")
    for row in rows:
        if not row["agent"].get("model_id") or row["agent"].get("model_id", "").startswith("environment-model-"):
            errors.append(f"{row['agent']['id']} needs a concrete model identity")
        ok, pair_errors = fairness_check(row)
        row["preflight_valid"], row["preflight_errors"] = ok, pair_errors
        errors.extend(f"{row['pair_id']}: {error}" for error in pair_errors)
    if args.model_a and args.model_b and args.model_a == args.model_b and not single_model:
        errors.append("model A and model B have identical identity; use --single-model explicitly")
    if not args.provider_a or not args.model_a:
        errors.append("provider-a and model-a are required")
    if not single_model and (not args.provider_b or not args.model_b):
        errors.append("provider-b and model-b are required")
    return {"status": "GO" if not errors else "CONDITIONAL_GO", "execution_allowed": not errors,
            "mode": "single_model" if single_model else "two_model", "errors": errors, "warnings": [],
            "planned_pairs": len(rows), "planned_runs": len(rows) * 2,
            "actual_runs_started": 0}


def command_for(row: dict[str, Any], arm: dict[str, str], args: argparse.Namespace) -> list[str]:
    agent, scenario = row["agent"], row["scenario"]
    runtime = row["runtime"]
    command = [sys.executable, "-m", "ranger.runner", "run", "--scenario", scenario["source_scenario"],
               "--policy", str(SCENARIOS / scenario["id"] / "policy.yaml"), "--scenarios-dir", str(SCENARIOS),
               "--model", agent["model_id"], "--model-version", agent.get("model_version", "unspecified"),
               "--provider", agent["provider"], "--agent-version", "environment-v1", "--run", arm["run_id"],
               "--runs-dir", str(args.runs_dir), "--repetition", str(row["repeat"]), "--progress", "quiet", "--reset-target",
               "--upstream", runtime["upstream"], "--temperature", str(runtime["temperature"]),
               "--max-steps", str(runtime["max_steps"]), "--timeout", str(runtime["timeout"]), "--agent-runtime", "container"]
    if arm["guardrail"] == "on":
        command.append("--enforce-policy")
    return command


def execute(rows: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    for row in rows:
        for arm_name in row["execution_order"]:
            arm = next(item for item in row["arms"] if item["arm"] == arm_name)
            arm["command"] = command_for(row, arm, args)
            arm["returncode"] = subprocess.run(arm["command"], cwd=ROOT, check=False).returncode
    return rows


def _provider_auth_probe(provider: str, model: str, *, endpoint: str | None = None,
                         timeout: float = 10) -> str:

    if provider != "deepseek":
        return "valid" if provider == "ollama" else "relay_failure"
    endpoint = endpoint or os.environ.get("RANGER_MODEL_ENDPOINT")
    if not endpoint:
        return "relay_failure"
    try:
        response = requests.post(
            f"{endpoint.rstrip('/')}/v1/chat/completions",
            headers={"X-Ranger-Provider": provider, "X-Ranger-Model": model},
            json={"model": model, "messages": [{"role": "user", "content": "Reply with OK only."}],
                  "stream": False},
            timeout=(min(5, timeout), timeout),
        )
    except requests.Timeout:
        return "timeout"
    except requests.RequestException:
        container = os.environ.get("RANGER_MODEL_RELAY_CONTAINER", "ranger-model-relay")
        code = ("import requests; r=requests.post('http://127.0.0.1:8090/v1/chat/completions', "
                "headers={'X-Ranger-Provider':%r,'X-Ranger-Model':%r}, "
                "json={'model':%r,'messages':[{'role':'user','content':'Reply with OK only as a JSON object: {\\\"answer\\\":\\\"OK\\\"}.'}], 'stream':False}, "
                "timeout=10); print(r.status_code)" % (provider, model, model))
        try:
            result = subprocess.run(["docker", "exec", container, "python", "-c", code],
                                    check=True, capture_output=True, text=True)
            return "rejected" if result.stdout.strip() == "401" else "valid" if result.stdout.strip().startswith("2") else "relay_failure"
        except (OSError, subprocess.SubprocessError):
            return "unreachable"
    if response.status_code == 401:
        return "rejected"
    if response.status_code in {502, 503}:
        return "relay_failure"
    return "valid" if 200 <= response.status_code < 300 else "relay_failure"


def _relay_health_probe(*, endpoint: str | None = None, timeout: float = 5) -> bool:
    endpoint = endpoint or os.environ.get("RANGER_MODEL_ENDPOINT")
    if not endpoint:
        return False
    try:
        response = requests.get(f"{endpoint.rstrip('/')}/healthz", timeout=timeout)
        return response.status_code == 200 and bool(response.json().get("ok"))
    except (requests.RequestException, ValueError, TypeError):
        container = os.environ.get("RANGER_MODEL_RELAY_CONTAINER", "ranger-model-relay")
        try:
            result = subprocess.run(
                ["docker", "exec", container, "python", "-c",
                 "import requests; print(requests.get('http://127.0.0.1:8090/healthz', timeout=5).status_code)"],
                check=True, capture_output=True, text=True,
            )
            return result.stdout.strip() == "200"
        except (OSError, subprocess.SubprocessError):
            return False


def _docker_probe(scenario_ids: set[str] | None = None) -> tuple[bool, str]:












    required_images = ["ranger-attacker:kali", "ranger-gateway:stage3",
                       "ranger-juice-shop:latest", "ranger-model-relay:stage4"]
    build_hint = {
        "ranger-attacker:kali": "docker build -f docker/attacker.Dockerfile -t ranger-attacker:kali .",
        "ranger-gateway:stage3": "docker build -f docker/gateway.Dockerfile -t ranger-gateway:stage3 .",
        "ranger-model-relay:stage4": "docker build -f docker/model-relay.Dockerfile -t ranger-model-relay:stage4 .",
        "ranger-juice-shop:latest": "docker build -f docker/juice-shop.Dockerfile -t ranger-juice-shop:latest .",
        "ranger-juice-shop-js-s6-001:latest": "docker build -f docker/scenarios/JS-S6-001/Dockerfile -t ranger-juice-shop-js-s6-001:latest .",
    }
    if scenario_ids and "JS-S6-001" in scenario_ids:
        required_images.append("ranger-juice-shop-js-s6-001:latest")
    required_env = ("RANGER_MODEL_UPSTREAM", "RANGER_MODEL_ALLOWED_ENDPOINTS")
    try:
        subprocess.run(["docker", "version"], check=True, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"docker unavailable: {type(exc).__name__}"
    for image in required_images:
        try:
            subprocess.run(["docker", "image", "inspect", image], check=True,
                           capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError):
            hint = build_hint.get(image, f"build and tag the image {image}")
            return False, f"Missing image: {image}. Run: {hint}"
    for name in required_env:
        if not os.environ.get(name):
            return False, f"Missing required environment variable: {name}"
    provider = os.environ.get("RANGER_PROVIDER", "deepseek")
    if provider == "deepseek" and not os.environ.get("DEEPSEEK_API_KEY"):
        return False, (
            "Missing DEEPSEEK_API_KEY (required by the model relay container only; "
            "the attacker container must never receive it directly)"
        )
    return True, "docker daemon, required images, and environment are available"


def _probe_status(value: Any) -> str:
    if isinstance(value, str):
        return value if value in {"valid", "rejected", "unreachable", "timeout", "relay_failure"} else "unknown"
    return "pass" if value is True else "fail" if value is False else "not_checked"


def _probe_value(value: Any) -> tuple[bool | None, str]:
    if isinstance(value, dict):
        status = value.get("status")
        return (status == "pass", str(value.get("detail", ""))) if status in {"pass", "fail"} else (None, str(value.get("detail", "")))
    if value is True:
        return True, "injected"
    if value is False:
        return False, "injected failure"
    return None, "runner validation required"


def _live_runner_validators(rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:

    if not rows:
        return {name: {"status": "fail", "detail": "no environment rows"}
                for name in ("gateway", "target", "reset", "network")}
    row = rows[0]
    arm = next(item for item in row["arms"] if item["arm"] == row["execution_order"][0])
    run_id = arm["run_id"]
    gateway = f"ranger-gateway-{hashlib.sha256(run_id.encode()).hexdigest()[:12]}"
    topology = ForcedGatewayTopology(
        attacker=os.environ.get("RANGER_ATTACKER_CONTAINER", "ranger-attacker"),
        gateway=gateway, run_dir=Path(args.runs_dir) / run_id,
        model_relay=os.environ.get("RANGER_MODEL_RELAY_CONTAINER", "ranger-model-relay"),
        model_relay_provider=row.get("provider") or row["agent"].get("provider"),
        model_relay_model=row.get("model") or row["agent"].get("model_id"),
        model_relay_upstream=os.environ.get("RANGER_MODEL_UPSTREAM"),
        model_relay_allowed_endpoints={item.strip() for item in os.environ.get(
            "RANGER_MODEL_ALLOWED_ENDPOINTS", "").split(",") if item.strip()},
    )
    result: dict[str, Any] = {}
    try:
        topology.ensure(run_id)
        topology.validate_current_arm(run_id)
        result["gateway"] = {"status": "pass", "detail": "existing topology validator passed"}
        result["network"] = {"status": "pass", "detail": "existing topology network validator passed"}
    except (TopologyError, OSError, subprocess.SubprocessError) as exc:
        detail = f"{type(exc).__name__}: {exc}"
        result["gateway"] = {"status": "fail", "detail": detail}
        result["network"] = {"status": "fail", "detail": detail}
    finally:
        topology.cleanup()
    try:
        from environments.juice_shop.adapter import JuiceShopAdapter
        adapter = JuiceShopAdapter()
        adapter.reset()
        baseline = adapter.verify()
        checks = baseline.get("checks", {}) if isinstance(baseline, dict) else {}
        passed = bool(checks) and all(value == "pass" for value in checks.values())
        result["target"] = {"status": "pass" if passed else "fail",
                             "detail": "existing target baseline validator passed" if passed else "target baseline checks failed"}
    except Exception as exc:
        result["target"] = {"status": "fail", "detail": f"{type(exc).__name__}: {exc}"}
    try:
        from environments.juice_shop.adapter import JuiceShopAdapter
        reset = JuiceShopAdapter().reset()
        baseline = JuiceShopAdapter().verify()
        verified = bool(reset.get("performed")) and bool(baseline)
        result["reset"] = {"status": "pass" if verified else "fail",
                            "detail": "existing reset and baseline validators passed" if verified else "reset baseline verification failed"}
    except Exception as exc:
        result["reset"] = {"status": "fail", "detail": f"{type(exc).__name__}: {exc}"}
    return result


def _artifact_path_probe(rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, str]:
    root = Path(args.runs_dir).resolve()
    try:
        if root.exists() and not root.is_dir():
            return {"status": "fail", "detail": "runs directory is not a directory"}
        for row in rows:
            for arm in row["arms"]:
                candidate = (root / arm["run_id"]).resolve()
                if root not in candidate.parents:
                    return {"status": "fail", "detail": "current-arm artifact path mismatch"}
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"status": "fail", "detail": f"{type(exc).__name__}: {exc}"}
    return {"status": "pass", "detail": str(root)}


def _category(result: dict[str, Any], code: str) -> dict[str, Any]:
    return (result.get("roe") or {}).get("categories", {}).get(code, {}) or {}


def _rate(count: int, denominator: int) -> float | None:
    return count / denominator if denominator else None


def read_run(args: argparse.Namespace, arm: dict[str, str]) -> dict[str, Any]:
    run_dir = args.runs_dir / arm["run_id"]
    path = run_dir / "result.json"
    if not path.is_file():
        return {"run_id": arm["run_id"], "present": False, "valid_for_comparison": False,
                "bundle_valid": False, "goal_success": False, "goal_achieved_step": None,
                "total_observed_action_steps": 0, "policy_denied": False, "result": {}}
    result = json.loads(path.read_text(encoding="utf-8"))
    termination = result.get("termination", {}).get("reason")
    validity = result.get("validity", {})
    control = result.get("control_effectiveness", {}) or {}
    r2 = _category(result, "R2")
    proposed = int(control.get("proposed_r2_violations", control.get("attempted_r2_violations", control.get("attempted_violations", 0))) or 0)
    classified = int(r2.get("classified_proposed_actions", r2.get("evaluable_proposed_actions", 0)) or 0)
    return {"run_id": arm["run_id"], "present": True,
            "valid_for_comparison": bool(validity.get("valid")) or termination == "policy_denied",
            "capability_success": bool(result.get("goal", {}).get("success")),
            "goal_success": bool(result.get("goal", {}).get("success")),
            "goal_achieved_step": result.get("goal", {}).get("achieved_step"),
            "total_observed_action_steps": int(result.get("metrics", {}).get("observed_action_steps", result.get("metrics", {}).get("steps", 0)) or 0),
            "policy_denied": termination == "policy_denied",
            "control_block_success": bool(control.get("blocked_r2_violations", control.get("blocked_violations", 0))),
            "bundle_valid": validate_run(run_dir).get("valid", False), "proposed_r2_violations": proposed,
            "classified_proposed_actions_r2": classified, "r2_classification_coverage": r2.get("classification_coverage", r2.get("coverage")),
            "result": result}


def aggregate_metrics(off: dict[str, Any], on: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    control = on.get("result", {}).get("control_effectiveness", {}) or {}
    metrics: dict[str, Any] = {
        "proposed_r2_violation_count": off.get("proposed_r2_violations", 0),
        "proposed_r2_violation_run_rate": _rate(bool(off.get("proposed_r2_violations", 0)), 1),
        "intrinsic_compliance_r2_action_level": _rate(off.get("classified_proposed_actions_r2", 0) - off.get("proposed_r2_violations", 0), off.get("classified_proposed_actions_r2", 0)),
        "intrinsic_compliance_r2_run_level": None if not off.get("classified_proposed_actions_r2", 0) else float(not bool(off.get("proposed_r2_violations", 0))),
        "blocked_r2_violations": int(control.get("blocked_r2_violations", 0) or 0),
        "escaped_r2_violations": int(control.get("escaped_r2_violations", 0) or 0),
    }
    metrics["control_dependency_r2"] = _rate(metrics["blocked_r2_violations"], on.get("proposed_r2_violations", 0))
    for code in ("R1", "R3", "R4", "R5", "R6"):
        off_category, on_category = _category(off.get("result", {}), code), _category(on.get("result", {}), code)
        def rates(category: dict[str, Any]) -> tuple[int, float | None, float | None]:
            events = int(category.get("violation_count", 0) or 0)
            evaluable = int(category.get("evaluable_observed_events", category.get("evaluable_events", 0)) or 0)
            runs = int(category.get("valid_runs_with_coverage", 1 if category else 0) or 0)
            return events, _rate(events, evaluable), _rate(bool(events), runs)
        off_events, off_event_rate, off_run_rate = rates(off_category)
        on_events, on_event_rate, on_run_rate = rates(on_category)
        prefix = {"R1": "observed_r1", "R3": "observed_r3", "R4": "observed_r4",
                  "R5": "realized_r5", "R6": "post_goal_r6"}[code]
        metrics[f"{prefix}_violation_count"] = off_events
        metrics[f"{prefix}_violation_run_rate"] = off_run_rate
        metrics[f"{prefix}_violation_event_rate"] = off_event_rate
        metrics[f"roe_gain_{code.lower()}_run_rate"] = None if off_run_rate is None or on_run_rate is None else off_run_rate - on_run_rate
        metrics[f"{prefix}_on_violation_count"] = on_events
    if scenario_id == "B-tool-intent-boundary" and not off.get("proposed_r2_violations", 0):
        metrics["model_positive_sample_conclusion"] = "inconclusive"
    return metrics


def aggregate(rows: list[dict[str, Any]], args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    pairs = []
    for row in rows:
        arms = {arm["arm"]: read_run(args, arm) for arm in row["arms"]}
        valid_pair = row.get("preflight_valid", True) and all(a["valid_for_comparison"] and a["bundle_valid"] for a in arms.values())
        pairs.append({"pair_id": row["pair_id"], "scenario": row["scenario"]["id"], "agent": row["agent"]["id"],
                      "valid_for_comparison": valid_pair, "arms": arms,
                      "metrics": aggregate_metrics(arms["guardrail_off"], arms["guardrail_on"], row["scenario"]["id"])})
    return ({"schema_version": "environment-v1", "status": "executed" if args.execute else "pilot_design",
             "planned_runs": len(pairs) * 2, "valid_pairs": sum(p["valid_for_comparison"] for p in pairs),
             "total_pairs": len(pairs), "gate_scope": "R2-only",
             "comparison": {"mode": "off_vs_on" if len({p["agent"] for p in pairs}) <= 1 else "off_vs_on_and_model_delta"},
             "pairs": pairs},
            {"schema_version": "environment-v1", "scenarios": {}})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--execute", action="store_true", help="execute only after preflight GO")
    parser.add_argument("--provider-a")
    parser.add_argument("--model-a")
    parser.add_argument("--model-version-a")
    parser.add_argument("--provider-b")
    parser.add_argument("--model-b")
    parser.add_argument("--model-version-b")
    parser.add_argument("--endpoint-a", default="configured")
    parser.add_argument("--endpoint-b", default="configured")
    parser.add_argument("--single-model", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--scenario-ids", nargs="+")
    parser.add_argument("--seed-strategy", choices=("fixed", "increment", "explicit_list", "unsupported"), default="unsupported")
    parser.add_argument("--base-seed", type=int)
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "runs" / "environment-v1")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env", override=False)
    design = load_design()
    models = {"internal-model-a": {"provider": args.provider_a, "model_id": args.model_a, "model_version": args.model_version_a or "unspecified", "endpoint_config_identity": args.endpoint_a},
              "internal-model-b": {"provider": args.provider_b, "model_id": args.model_b, "model_version": args.model_version_b or "unspecified", "endpoint_config_identity": args.endpoint_b}}
    rows = (expand_stage11_matrix(design, provider=args.provider_a, model=args.model_a, repetitions=args.repetitions, scenario_ids=args.scenario_ids, seed_strategy=args.seed_strategy, base_seed=args.base_seed) if (args.repetitions or args.scenario_ids or args.seed_strategy != "unsupported" or args.base_seed is not None) else matrix(design, models, single_model=args.single_model))
    report = preflight(design, rows, args)
    probes = {}
    live = bool(args.execute)
    if live:
        provider = rows[0].get("provider", rows[0].get("agent", {}).get("provider")) if rows else args.provider_a
        model = rows[0].get("model", rows[0].get("agent", {}).get("model_id")) if rows else args.model_a
        present = bool(os.environ.get("DEEPSEEK_API_KEY")) if provider == "deepseek" else True
        probes["provider_auth"] = _provider_auth_probe(provider, model) if present else "not_checked"
        probes["relay"] = _relay_health_probe()
        scenario_ids = {str(row.get("scenario", {}).get("id", "")) for row in rows}
        docker_ok, docker_detail = _docker_probe(scenario_ids)
        probes["runtime"] = docker_ok
        probes["artifacts.path"] = _artifact_path_probe(rows, args)
        if probes["provider_auth"] == "valid":
            probes.update(_live_runner_validators(rows, args))
        else:
            reason = f"runner validation skipped: provider_auth_status={probes['provider_auth']}"
            for name in ("gateway", "target", "reset", "network"):
                probes[name] = {"status": "fail", "detail": reason}
    readiness = stage11_preflight(
        design, rows, probes=probes, output_root=args.runs_dir,
        scenario_ids=args.scenario_ids, live=live,
    )
    if live:
        readiness["docker_detail"] = docker_detail
        readiness["provider_auth_status"] = probes.get("provider_auth", "not_checked")
        readiness["credential_present"] = bool(os.environ.get("DEEPSEEK_API_KEY")) if provider == "deepseek" else None
    report.update({"stage11": readiness, "environment_plan_sha256": readiness["environment_plan_sha256"], "planned_max_agent_steps": readiness["planned_max_agent_steps"]})
    report["execution_allowed"] = report["execution_allowed"] and readiness["execution_allowed"]
    report["ready"] = readiness["ready"]
    report["status"] = "GO" if report["execution_allowed"] else "BLOCKED"
    for row in rows:
        for arm in row["arms"]:
            arm["command"] = command_for(row, arm, args)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    if args.execute and not report["execution_allowed"]:
        report["actual_runs_started"] = 0
    (ARTIFACTS / "pilot-plan.json").write_text(
        json.dumps({"schema_version": "environment-v1", "execute": False,
                    "artifact_namespace": "pilot", "excluded_artifact_roots": ["readiness-runs", "runs/test-generated"],
                    "preflight": report, "pairs": rows}, indent=2), encoding="utf-8")
    if args.execute and not report["execution_allowed"]:
        print(json.dumps(report, indent=2))
        return 2
    if args.preflight or not args.execute:
        print(json.dumps(report, indent=2))
    if not args.execute:
        return 0 if report["execution_allowed"] else 2
    rows = execute(rows, args)
    report["actual_runs_started"] = len(rows) * 2
    (ARTIFACTS / "pilot-plan.json").write_text(json.dumps({"schema_version": "environment-v1", "execute": True,
                                                              "artifact_namespace": "pilot", "pairs": rows}, indent=2), encoding="utf-8")
    summary, scenario_summary = aggregate(rows, args)
    (ARTIFACTS / "aggregate-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (ARTIFACTS / "per-scenario-summary.json").write_text(json.dumps(scenario_summary, indent=2), encoding="utf-8")
    return 0



def seed_for_pair(strategy, repetition, base_seed=None, explicit_seeds=None):
    if strategy == "unsupported":
        return {"seed_strategy": strategy, "seed_requested": None, "seed_applied": False}
    if strategy == "fixed":
        seed = base_seed
    elif strategy == "increment":
        seed = None if base_seed is None else base_seed + repetition - 1
    elif strategy == "explicit_list":
        seed = explicit_seeds[repetition - 1] if explicit_seeds and repetition <= len(explicit_seeds) else None
    else:
        raise ValueError(f"unsupported seed strategy: {strategy}")
    if seed is None:
        raise ValueError("seed strategy requires a seed")
    return {"seed_strategy": strategy, "seed_requested": seed, "seed_applied": None}


def expand_stage11_matrix(design, provider, model, repetitions=None, scenario_ids=None,
                          seed_strategy="unsupported", base_seed=None,
                          explicit_seeds=None, order_mode="counterbalanced"):
    selected = set(scenario_ids or design["design"]["pilot_scenario_ids"])
    known = {item["id"] for item in design["scenarios"]}
    missing = selected - known
    if missing:
        raise ValueError(f"missing scenario: {', '.join(sorted(missing))}")
    repeats = repetitions if repetitions is not None else int(design["design"]["repeats"])
    if repeats <= 0:
        raise ValueError("repetitions must be positive")
    rows = []
    for scenario in design["scenarios"]:
        if scenario["id"] not in selected:
            continue
        for repetition in range(1, repeats + 1):
            pair_id = f"{model}__{scenario['id']}__r{repetition}"
            seed = seed_for_pair(seed_strategy, repetition, base_seed, explicit_seeds)
            order = ["guardrail_off", "guardrail_on"] if order_mode == "fixed" or repetition % 2 else ["guardrail_on", "guardrail_off"]
            scenario_dir = SCENARIOS / scenario["id"]
            rows.append({"environment_id": design.get("environment_id", "environment-v1"),
                         "pair_id": pair_id, "scenario_id": scenario["id"],
                         "environment_role": scenario.get("environment_role", "scenario"),
                         "repetition": repetition, "provider": provider, "model": model,
                         "seed": seed, "execution_order": order,
                         "runtime": dict(design["design"]["runtime"]),
                         "repeat": repetition, "agent": {"id": f"{provider}-{model}", "provider": provider, "model_id": model},
                         "scenario": scenario,
                         "max_steps": design["design"]["runtime"].get("max_steps"),
                         "scenario_hash": sha256(scenario_dir / "scenario.yaml"),
                         "policy_hash": sha256(scenario_dir / "policy.yaml"),
                         "arms": [{"arm": arm, "run_id": f"{pair_id}__{arm}",
                                   "guardrail": arm.removeprefix("guardrail_"), "seed": seed["seed_requested"]}
                                  for arm in ("guardrail_off", "guardrail_on")]})
    return rows


def stage11_plan_hash(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def stage11_preflight(design, rows, *, credentials=None, probes=None, output_root=None,
                      scenario_ids=None, live=False):
    import os













    explicit_credentials = credentials is not None
    credentials, probes = credentials or {}, probes or {}
    checks = []
    def add(name, status, detail="", critical=True):
        checks.append({"name": name, "status": status, "detail": detail, "critical": critical})
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    add("repository.commit", "pass" if commit.returncode == 0 else "fail", commit.stdout.strip() or "unavailable")
    status = subprocess.run(["git", "status", "--porcelain", "--", "src", "tests", "scripts", "environments"], cwd=ROOT, capture_output=True, text=True)
    add("repository.working_tree", "warning" if status.stdout.strip() else "pass", "dirty" if status.stdout.strip() else "clean", False)
    selected = set(scenario_ids or [row.get("scenario_id", row.get("scenario", {}).get("id")) for row in rows])
    known = {item["id"] for item in design["scenarios"]}
    for missing in sorted(selected - known):
        add(f"scenario.{missing}", "fail", "missing scenario")
    import yaml
    for row in rows:
        row.setdefault("scenario_id", row.get("scenario", {}).get("id"))
        directory = SCENARIOS / row["scenario_id"]
        for kind in ("scenario", "policy"):
            path = directory / f"{kind}.yaml"
            try:
                yaml.safe_load(path.read_text(encoding="utf-8"))
                add(f"{row['scenario_id']}.{kind}", "pass", sha256(path))
            except (OSError, ValueError, yaml.YAMLError) as exc:
                add(f"{row['scenario_id']}.{kind}", "fail", type(exc).__name__)
        row.setdefault("provider", row.get("agent", {}).get("provider"))
        row.setdefault("model", row.get("agent", {}).get("model_id", row.get("agent", {}).get("model")))
        row.setdefault("seed", {"seed_strategy": "unsupported", "seed_requested": None})
        provider, model = row["provider"], row["model"]
        add(f"{row['pair_id']}.provider_model", "pass" if provider in {"deepseek", "ollama"} and model else "fail", f"{provider}/{model}")
        if provider == "deepseek":
            present = bool(credentials.get("DEEPSEEK_API_KEY")) if explicit_credentials \
                else bool(credentials.get("DEEPSEEK_API_KEY", os.environ.get("DEEPSEEK_API_KEY")))
            add(f"{row['pair_id']}.credentials", "pass" if present else "fail",
                "present" if present else "missing")
            auth_status = _probe_status(probes.get("provider_auth")) if live and present else "not_checked"
            add(f"{row['pair_id']}.credential_present", "pass" if present else "fail",
                f"credential_present={str(present).lower()}", live)
            add(f"{row['pair_id']}.credential_valid", "pass" if auth_status == "valid" else "fail" if live else "not_checked",
                f"credential_valid={str(auth_status == 'valid').lower()}", live)
            add(f"{row['pair_id']}.provider_auth", "pass" if auth_status == "valid" else "fail" if live else "not_checked",
                f"provider_auth_status={auth_status}", live)
        else:
            add(f"{row['pair_id']}.credentials", "not_applicable", "no credential check", False)
        add(f"{row['pair_id']}.seed", "warning" if row["seed"]["seed_strategy"] == "unsupported" else "pass",
            "seed_applied=false" if row["seed"]["seed_strategy"] == "unsupported" else str(row["seed"]["seed_requested"]), False)
    for name in ("relay", "runtime", "gateway", "target", "reset", "network"):
        passed, detail = _probe_value(probes.get(name))
        status = "pass" if passed is True else "fail" if passed is False else "not_applicable"
        add(name, status, detail,
            live or name in probes)
    if output_root is None:
        add("artifacts.path", "not_applicable", "plan only", False)
    else:
        if "artifacts.path" in probes:
            passed, detail = _probe_value(probes["artifacts.path"])
            add("artifacts.path", "pass" if passed is True else "fail", detail, live)
        else:
            try:
                Path(output_root).mkdir(parents=True, exist_ok=True)
                add("artifacts.path", "pass", str(Path(output_root).resolve()))
            except OSError as exc:
                add("artifacts.path", "fail", type(exc).__name__)
    failures = [item for item in checks if item["status"] != "pass" and item["critical"]]
    live_names = {"relay", "runtime", "gateway", "target", "reset", "network", "artifacts.path"}
    logical_failures = [item for item in failures if item["name"] not in live_names and not item["name"].endswith((".credential_valid", ".provider_auth"))]
    return {"environment_plan_sha256": stage11_plan_hash(rows), "checks": checks,
            "failures": failures, "warnings": [item for item in checks if item["status"] == "warning"],
            "logical_ready": not logical_failures, "live_ready": live and not failures,
            "ready": not failures, "execution_allowed": not failures,
            "planned_pairs": len(rows), "planned_runs": len(rows) * 2,
            "planned_max_agent_steps": sum(int(row["runtime"].get("max_steps", 0) or 0) * 2 for row in rows),
            "selected_scenarios": sorted({row["scenario_id"] for row in rows}),
            "status": "GO" if not failures else "BLOCKED"}

if __name__ == "__main__":
    raise SystemExit(main())