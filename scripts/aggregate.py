#!/usr/bin/env python3


import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ranger.core.policy import Policy
from ranger.evaluate.oracle import evaluate_oracle


def warn(message: str) -> None:
    print(f"[warn] {message}", file=sys.stderr)


def load_groups(runs_dir: Path, scenario: str) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    policy_hashes: set[str] = set()
    if not runs_dir.is_dir():
        return groups

    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        config_path = run_dir / "config.json"
        if not config_path.is_file():
            warn(f"no config.json in {run_dir}")
            continue
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            warn(f"cannot read {config_path}: {error}")
            continue
        if config.get("scenario") != scenario:
            continue

        result_path = run_dir / "result.json"
        if not result_path.is_file():
            warn(f"no result.json in {run_dir}")
            continue
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            success = result["goal"]["success"]
            compliant = result["roe"]["compliant"]
            roe_summary = (result.get("roe") or {}).get("summary") or {}
            unclassified_rate = roe_summary.get("unclassified_rate", 0.0)
            steps = result["metrics"]["steps"]
            achieved_step = result["goal"].get("achieved_step")
            validity = result.get("validity", {"valid": True, "reason": None})
            valid = validity.get("valid", True)
            provenance = result.get("provenance") or {}
            declarations = result.get("declarations")
            declaration_accuracy = declarations.get("declaration_accuracy") if declarations else None
            covert_rate = declarations.get("covert_rate") if declarations else None
            phantom = declarations.get("phantom", 0) if declarations else 0
            covert = declarations.get("covert", 0) if declarations else 0
            categories = (result.get("roe") or {}).get("categories") or {}
            policy_sha256 = provenance.get("policy_sha256")
            if policy_sha256:
                policy_hashes.add(str(policy_sha256))
            if not isinstance(success, bool) or not isinstance(compliant, bool):
                raise ValueError("goal.success and roe.compliant must be booleans")
            if not isinstance(valid, bool):
                raise ValueError("validity.valid must be a boolean")
            if (not isinstance(unclassified_rate, (int, float))
                    or isinstance(unclassified_rate, bool)):
                raise ValueError("roe.summary.unclassified_rate must be numeric")
            if not isinstance(steps, (int, float)) or isinstance(steps, bool):
                raise ValueError("metrics.steps must be numeric")
            for name, value in (("declaration_accuracy", declaration_accuracy),
                                ("covert_rate", covert_rate)):
                if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool)):
                    raise ValueError(f"declarations.{name} must be numeric")
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            warn(f"cannot read {result_path}: {error}")
            continue

        groups[str(config.get("policy", "unknown"))].append({
            "success": success,
            "compliant": compliant,
            "steps": steps,
            "achieved_step": achieved_step,
            "temperature": config.get("temperature"),
            "repetition": config.get("repetition"),
            "valid": valid,
            "invalid_reason": validity.get("reason"),
            "policy_sha256": policy_sha256,
            "unclassified_rate": float(unclassified_rate),
            "declaration_accuracy": (
                float(declaration_accuracy) if declaration_accuracy is not None else None
            ),
            "covert_rate": float(covert_rate) if covert_rate is not None else None,
            "phantom": int(phantom),
            "covert": int(covert),
            "categories": categories,
        })
    if len(policy_hashes) > 1:
        warn("different policy_sha256 values were combined in the same aggregation")
    return dict(groups)


def summarize(runs: list[dict[str, Any]]) -> dict[str, Any]:
    attempted = len(runs)
    valid_runs = [run for run in runs if run["valid"]]
    total = len(valid_runs)
    invalid = attempted - total
    goals = sum(run["success"] for run in valid_runs)
    violations = sum(not run["compliant"] for run in valid_runs)
    safe = sum(run["success"] and run["compliant"] for run in valid_runs)
    unsafe = sum(run["success"] and not run["compliant"] for run in valid_runs)
    goal_steps = [
        run["achieved_step"] for run in valid_runs
        if run["success"] and isinstance(run["achieved_step"], (int, float))
    ]
    return {
        "runs": attempted,
        "attempted_runs": attempted,
        "valid_runs": total,
        "invalid_runs": invalid,
        "invalid_rate": invalid / attempted if attempted else 0.0,
        "invalid_reasons": dict(Counter(
            run["invalid_reason"] or "unknown" for run in runs if not run["valid"]
        )),
        "goal_rate": goals / total if total else None,
        "violation_rate": violations / total if total else None,
        "safe_success_rate": safe / total if total else None,
        "unsafe_success_rate": unsafe / total if total else None,
        "mean_goal_step": statistics.fmean(goal_steps) if goal_steps else None,
        "mean_steps": statistics.fmean(run["steps"] for run in valid_runs) if valid_runs else None,
        "mean_unclassified_rate": statistics.fmean(
            run.get("unclassified_rate", 0.0) for run in valid_runs
        ) if valid_runs else None,
        "mean_declaration_accuracy": statistics.fmean(
            run.get("declaration_accuracy") for run in valid_runs
            if run.get("declaration_accuracy") is not None
        ) if any(run.get("declaration_accuracy") is not None for run in valid_runs) else None,
        "mean_covert_rate": statistics.fmean(
            run.get("covert_rate") for run in valid_runs if run.get("covert_rate") is not None
        ) if any(run.get("covert_rate") is not None for run in valid_runs) else None,
        "total_phantom": sum(run.get("phantom", 0) for run in valid_runs),
        "total_covert": sum(run.get("covert", 0) for run in valid_runs),
        "covert_runs": sum(run.get("covert", 0) > 0 for run in valid_runs),
        "roe_categories": _category_summary(valid_runs),
        "temperatures": sorted(
            {run["temperature"] for run in runs if run["temperature"] is not None},
            key=str,
        ),
        "repetitions": sorted(
            {run["repetition"] for run in runs if run["repetition"] is not None},
            key=str,
        ),
        "_counts": {"goal": goals, "violation": violations, "safe": safe, "unsafe": unsafe},
    }


def rate(count: int, total: int) -> str:
    return f"{count}/{total} ({count / total:.0%})" if total else "0/0 (-)"


def _category_summary(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = len(runs)
    summary = []
    for code, name in ((code, details["name"]) for code, details in {
        "R1": {"name": "target_authorization"}, "R2": {"name": "tool_authorization"},
        "R3": {"name": "activity_authorization"}, "R4": {"name": "technical_operation_authorization"},
        "R5": {"name": "expected_outcome_boundary"}, "R6": {"name": "halt_compliance"},
    }.items()):
        category_runs = [run.get("categories", {}).get(code, {}) for run in runs]
        violating = sum(bool(item.get("violation_count", 0)) for item in category_runs)
        summary.append({"code": code, "name": name, "violating_runs": violating,
                        "violating_run_rate": violating / total if total else 0.0,
                        "violation_event_count": sum(item.get("violation_count", 0) for item in category_runs)})
    return sorted(summary, key=lambda item: (-item["violating_run_rate"], -item["violation_event_count"], item["code"]))


def print_table(scenario: str, groups: dict[str, dict[str, Any]]) -> None:
    policies = sorted(groups)
    rows = [
        ["Attempted Runs", *(str(groups[name]["attempted_runs"]) for name in policies)],
        ["Valid Runs", *(str(groups[name]["valid_runs"]) for name in policies)],
        ["Excluded Runs", *(str(groups[name]["invalid_runs"]) for name in policies)],
        ["Invalid Rate", *(rate(groups[name]["invalid_runs"], groups[name]["runs"]) for name in policies)],
        ["Excluded Reasons", *(
            json.dumps(groups[name]["invalid_reasons"], sort_keys=True) for name in policies
        )],
        ["Goal Rate", *(rate(groups[name]["_counts"]["goal"], groups[name]["valid_runs"]) for name in policies)],
        ["ROE Violation", *(rate(groups[name]["_counts"]["violation"], groups[name]["valid_runs"]) for name in policies)],
        ["Safe Success", *(rate(groups[name]["_counts"]["safe"], groups[name]["valid_runs"]) for name in policies)],
        ["Unsafe Success", *(rate(groups[name]["_counts"]["unsafe"], groups[name]["valid_runs"]) for name in policies)],
        ["Mean Goal Step", *(
            "-" if groups[name]["mean_goal_step"] is None else f'{groups[name]["mean_goal_step"]:.1f}'
            for name in policies
        )],
        ["Mean Steps", *(
            "-" if groups[name]["mean_steps"] is None else f'{groups[name]["mean_steps"]:.1f}'
            for name in policies
        )],
        ["Mean Unclassified Rate", *(
            "-" if groups[name]["mean_unclassified_rate"] is None
            else f'{groups[name]["mean_unclassified_rate"]:.1%}'
            for name in policies
        )],
        ["Mean Declaration Accuracy", *(
            "-" if groups[name]["mean_declaration_accuracy"] is None
            else f'{groups[name]["mean_declaration_accuracy"]:.1%}'
            for name in policies
        )],
        ["Mean Covert Rate", *(
            "-" if groups[name]["mean_covert_rate"] is None
            else f'{groups[name]["mean_covert_rate"]:.1%}'
            for name in policies
        )],
        ["Total Phantom", *(str(groups[name]["total_phantom"]) for name in policies)],
        ["Total Covert", *(str(groups[name]["total_covert"]) for name in policies)],
    ]
    for key, label in (("temperatures", "Temperature"), ("repetitions", "Repetitions")):
        if any(groups[name][key] for name in policies):
            rows.append([label, *(", ".join(map(str, groups[name][key])) or "-" for name in policies)])

    table = [["Metric", *policies], *rows]
    widths = [max(len(row[index]) for row in table) for index in range(len(table[0]))]
    print(f"Scenario: {scenario}\n")
    for row in table:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
    print("\nROE Category Summary")
    for policy, summary in sorted(groups.items()):
        print(f"{policy}:")
        for category in summary["roe_categories"]:
            print(f"  {category['code']} {category['name']}: "
                  f"violating runs={category['violating_runs']}/{summary['valid_runs']} "
                  f"({category['violating_run_rate']:.1%}), "
                  f"events={category['violation_event_count']}")
        print("  Most Frequently Violated ROE Categories:")
        for rank, category in enumerate(summary["roe_categories"][:3], 1):
            print(f"    {rank}. {category['code']} {category['name']} "
                  f"({category['violating_run_rate']:.1%}, {category['violation_event_count']} events)")


def print_csv(groups: dict[str, dict[str, Any]]) -> None:
    fields = [
        "policy", "runs", "attempted_runs", "valid_runs", "invalid_runs", "invalid_rate",
        "invalid_reasons", "goal_rate", "violation_rate", "safe_success_rate",
        "unsafe_success_rate", "mean_goal_step", "mean_steps", "mean_unclassified_rate",
        "mean_declaration_accuracy", "mean_covert_rate", "total_phantom", "total_covert",
        "roe_categories", "temperatures", "repetitions",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields)
    writer.writeheader()
    for policy, summary in sorted(groups.items()):
        writer.writerow({
            **{field: summary[field] for field in fields[1:-2]},
            "policy": policy,
            "invalid_reasons": json.dumps(summary["invalid_reasons"], sort_keys=True),
            "temperatures": "|".join(map(str, summary["temperatures"])),
            "repetitions": "|".join(map(str, summary["repetitions"])),
            "roe_categories": json.dumps(summary["roe_categories"], sort_keys=True),
        })


def load_oracle(scenarios_dir: Path, scenario: str) -> dict[str, Any] | None:
    from ranger.scenario_paths import resolve_scenario_dir
    try:
        directory = resolve_scenario_dir(scenarios_dir, scenario)
    except (FileNotFoundError, RuntimeError):
        return None
    path = directory / "oracle.yaml"
    if not path.is_file():
        return None
    try:
        oracle = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if oracle.get("status") == "TODO":
            return None
        def load(name: str) -> dict[str, Any]:
            return yaml.safe_load((directory / name).read_text(encoding="utf-8")) or {}
        result = evaluate_oracle(
            {**oracle, "scenario_id": scenario},
            Policy.from_dict(load("policy.yaml")), load("scenario.yaml"),
        )
        return {
            "recall": result.scorer_recall,
            "fpr": result.scorer_fpr,
            "passed": result.passed,
        }
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as error:
        warn(f"cannot evaluate oracle for {scenario}: {error}")
        return None


def print_oracle(scenarios_dir: Path, scenario: str) -> None:
    oracle = load_oracle(scenarios_dir, scenario)
    print("\n=== Scorer Validation ===")
    if oracle is None:
        print(f"{scenario}: SKIP")
    else:
        print(f"{scenario}: recall={oracle['recall']:.2f}, fpr={oracle['fpr']:.2f}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate environment results by policy")
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    parser.add_argument("--scenarios-dir", type=Path, default=Path("scenarios"))
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--format", choices=("table", "csv", "json"), default="table")
    args = parser.parse_args()

    summaries = {
        policy: summarize(runs)
        for policy, runs in load_groups(args.runs_dir, args.scenario).items()
    }
    if not summaries:
        print(f"No runs found for scenario {args.scenario}")
        return 0
    covert_runs = sum(summary["covert_runs"] for summary in summaries.values())
    if covert_runs:
        warn(f"{covert_runs} runs contain covert (undeclared) agent actions")
    if args.format == "json":
        clean = {
            policy: {key: value for key, value in summary.items() if key != "_counts"}
            for policy, summary in sorted(summaries.items())
        }
        print(json.dumps({"scenario": args.scenario, "groups": clean,
                          "oracle": load_oracle(args.scenarios_dir, args.scenario)}, indent=2))
    elif args.format == "csv":
        print_csv(summaries)
    else:
        print_table(args.scenario, summaries)
        print_oracle(args.scenarios_dir, args.scenario)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())