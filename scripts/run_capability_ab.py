#!/usr/bin/env python3


from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ranger.capability_ab import (
    MODES, aggregate, build_matrix, experiment_metadata, read_run, run_matrix,
    select_scenarios, write_outputs,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true", help="run the matrix; otherwise only print the plan")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "artifacts" / "capability_ab")
    parser.add_argument("--scenarios-dir", type=Path, default=ROOT / "scenarios")
    parser.add_argument("--scenario", action="append", dest="scenarios")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--model", default="qwen2.5:3b")
    parser.add_argument("--provider", default="ollama")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--upstream", default=None)
    parser.add_argument("--agent-runtime", choices=("host", "container"), default="host")
    parser.add_argument("--rebuild-attacker", action="store_true")
    args = parser.parse_args()

    scenarios = select_scenarios(args.scenarios_dir, args.scenarios)
    rows = build_matrix(scenarios, MODES, args.repetitions)
    experiment = experiment_metadata(
        ROOT, args.scenarios_dir, scenarios, model=args.model, provider=args.provider,
        temperature=args.temperature, seed=args.seed, max_steps=args.max_steps,
        repetitions=args.repetitions,
    )
    if not args.execute:
        print(json.dumps({"experiment": experiment, "planned_runs": len(rows), "matrix": rows},
                         indent=2, ensure_ascii=False))
        return 0

    if args.rebuild_attacker:
        try:
            subprocess.run(
                ["docker", "build", "-f", "docker/attacker.Dockerfile",
                 "-t", "ranger-attacker:kali", "."],
                cwd=ROOT,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"attacker image rebuild failed: {exc}", file=sys.stderr)
            return 1

    runs_dir = args.artifact_dir / "runs"
    run_matrix(ROOT, rows, model=args.model, provider=args.provider, temperature=args.temperature,
               seed=args.seed, max_steps=args.max_steps, timeout=args.timeout, runs_dir=runs_dir,
               scenarios_dir=args.scenarios_dir, upstream=args.upstream, agent_runtime=args.agent_runtime)
    measured = [read_run(runs_dir, row) for row in rows]
    summary = aggregate(measured)
    experiment["completed_runs"] = len(measured)
    write_outputs(args.artifact_dir, experiment, measured, summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())