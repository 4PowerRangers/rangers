"""Command-line parser definitions for the benchmark runner."""

import argparse
from pathlib import Path

from .agent.runtime_control import DEFAULT_ATTACKER_CONTAINER

SCENARIOS_DIR = Path("scenarios")
ENVIRONMENTS_DIR = Path("environments")

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
    run.add_argument("--repetition", type=int, default=None)
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
    experiment.add_argument("--experiments-dir", type=Path, default=Path("artifacts"))
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