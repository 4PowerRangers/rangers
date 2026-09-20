"""CLI for replaying events through independent evaluators."""

import argparse
import json
from pathlib import Path

import yaml

from ..core.policy import Policy
from ..core.run import RunConfig
from .pipeline import evaluate_run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ranger evaluator")
    parser.add_argument("--scenario", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--run", required=True)
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    parser.add_argument(
        "--environment", type=Path, default=None,
        help="Optional environment.yaml providing lifecycle stage rules for progress evaluation",
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Replay output path (default: run directory/replay-result-v2.json)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_dir = args.runs_dir / args.run
    config_path = run_dir / "config.json"
    events_path = run_dir / "events.jsonl"
    if not config_path.exists() or not events_path.exists():
        raise SystemExit(f"run artifacts not found: {run_dir}")
    config = RunConfig.from_dict(json.loads(config_path.read_text(encoding="utf-8")))
    scenario = yaml.safe_load(args.scenario.read_text(encoding="utf-8"))
    policy = Policy.from_dict(yaml.safe_load(args.policy.read_text(encoding="utf-8")))
    environment = (
        yaml.safe_load(args.environment.read_text(encoding="utf-8"))
        if args.environment else None
    )
    result = evaluate_run(events_path, scenario, policy, config, environment=environment)
    output_path = args.output or (run_dir / "replay-result-v2.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"run_id: {result.run_id}")
    print(f"goal.success: {result.goal.success}")
    print(f"progress.current_stage: {result.progress.current_stage} ({result.progress.stage_name})")
    print(f"progress.completed_stages: {result.progress.completed_stages}")
    print(f"roe.compliant: {result.roe.compliant}")
    print(f"roe.violations: {len(result.roe.violations)}")
    print(f"saved: {output_path}")


if __name__ == "__main__":
    main()
