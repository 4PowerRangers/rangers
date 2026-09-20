from __future__ import annotations

import argparse
import json
import os

import traceback
from pathlib import Path
from typing import Any


def _run_dir(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = Path("/app/runs") / value
    resolved = path.resolve()
    root = Path("/app/runs").resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError(f"run_dir must be under /app/runs, got: {value!r}")
    return resolved


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=_run_dir)
    parser.add_argument("--scenario")
    parser.add_argument("--gateway-url")
    parser.add_argument("--provider")
    parser.add_argument("--model")
    parser.add_argument("--max-steps", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--run-token-budget", type=int)
    parser.add_argument("--seed", type=int)
    return parser.parse_args(argv)


def _load_input(run_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    input_path = run_dir / "container_input.json"
    if not input_path.is_file():
        raise FileNotFoundError(f"missing container input: {input_path}")
    data: dict[str, Any] = json.loads(input_path.read_text(encoding="utf-8"))
    for key, value in (
        ("scenario", args.scenario), ("gateway_url", args.gateway_url),
        ("provider", args.provider), ("model", args.model),
        ("max_steps", args.max_steps), ("temperature", args.temperature),
        ("max_tokens", args.max_tokens),
        ("run_token_budget", getattr(args, "run_token_budget", None)),
        ("seed", args.seed),
    ):
        if value is not None:
            data.setdefault(key, value)
    return data


def _validate_gateway_url(gateway_url: str) -> None:
    from urllib.parse import urlsplit
    host = (urlsplit(gateway_url).hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "0.0.0.0"}:
        raise ValueError(
            f"container mode refuses a host-loopback gateway_url ({gateway_url!r}); "
            "the attacker container cannot resolve the Host's loopback interface, and "
            "using it would silently either fail closed or route around the isolated "
            "attacker-net/target-net topology. gateway_url must be a Docker network "
            "DNS name (e.g. http://ranger-gateway-<hash>:8080)."
        )


def _validate_model_endpoint(model_endpoint: str) -> None:
    from urllib.parse import urlsplit
    host = (urlsplit(model_endpoint).hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "0.0.0.0"}:
        raise ValueError(
            f"container mode refuses a host-loopback model_endpoint ({model_endpoint!r}); "
            "it must be the model relay container's DNS name so the attacker never talks "
            "to a direct provider endpoint or needs a provider API key."
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir: Path = args.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)
    outcome_path = run_dir / "container_outcome.json"
    error_path = run_dir / "container_error.txt"
    trace_path = run_dir / "container_trace.jsonl"
    lifecycle_path = run_dir / "container_lifecycle.jsonl"
    invocations_path = run_dir / "container_invocations.jsonl"

    try:
        payload = _load_input(run_dir, args)
        gateway_url = str(payload["gateway_url"])
        model_endpoint = str(payload["model_endpoint"])
        _validate_gateway_url(gateway_url)
        _validate_model_endpoint(model_endpoint)

        os.environ["RANGER_MODEL_ENDPOINT"] = model_endpoint
        os.environ["RANGER_PROVIDER"] = str(payload.get("provider") or "")
        os.environ["RANGER_MODEL"] = str(payload.get("model") or "")
        os.environ.pop("DEEPSEEK_API_KEY", None)

        from ranger.agent.runtime import run_episode
        from ranger.core.policy import Policy
        from ranger.agent import tool_runner
        from ranger.agent.command_registry import build_tool_registry, model_tool_schemas

        policy_doc = payload.get("policy")
        policy = Policy.from_dict(policy_doc) if policy_doc else None
        command_profile = payload.get("command_profile") or {"command_tools": []}
        available_command_tools = tool_runner.materialize_profile(command_profile)
        registry = build_tool_registry(tool_runner.run, available_command_tools)
        tool_calls: list[dict[str, Any]] = []
        used_tools: set[str] = set()
        (run_dir / "command-availability.json").write_text(json.dumps({
            "agent_command_path": tool_runner.agent_command_path(),
            "profile": command_profile,
            "available_command_tools": available_command_tools,
            "tool_schemas": model_tool_schemas(registry),
            "executable_probe": {
                name: {"present": bool(tool_runner.resolve_executable(name)),
                       "path": tool_runner.resolve_executable(name)}
                for name in tool_runner.DEFAULT_TOOL_CANDIDATES
            },
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        def append_jsonl(path: Path, record: dict[str, Any]) -> None:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

        def on_step(record: dict[str, Any]) -> None:
            if record.get("action") == "run_tool" and record.get("argv"):
                tool = str(record["argv"][0])
                used_tools.add(tool)
                tool_calls.append({"tool": tool, "step": record.get("step"),
                                   "status": (record.get("process") or {}).get("status"),
                                   "arguments": {"argv": record.get("argv")},
                                   "result": record.get("process")})
            append_jsonl(trace_path, {"run_id": payload["run_id"], **record})

        def on_invocation(record: dict[str, Any]) -> None:
            append_jsonl(invocations_path, {
                "run_id": payload["run_id"],
                **record,
                "container": payload.get("attacker_container", "ranger-attacker"),
            })

        def on_lifecycle(stage: str, action_id: str, step: int,
                         raw_action: dict, details: dict | None,
                         normalized_action: dict) -> None:
            append_jsonl(lifecycle_path, {
                "run_id": payload["run_id"], "seq": step - 1, "action_id": action_id,
                "actor": "agent", "source": "container_episode", "stage": stage,
                "raw_action": raw_action if stage == "proposed" else None,
                "reference": None if stage == "proposed" else {"action_step": step},
                "normalized_action": normalized_action,
                "decision": (details or {}).get("decision"),
                "reason": (details or {}).get("reason"),
            })

        def on_progress(event_type: str, step: int, detail: dict) -> None:
            append_jsonl(run_dir / "container_progress.jsonl", {
                "event_type": event_type, "step": step, "detail": detail,
            })

        outcome = run_episode(
            str(payload["mission"]), gateway_url, int(payload["max_steps"]),
            provider=payload.get("provider"), model=payload.get("model"),
            temperature=payload.get("temperature"), on_step=on_step,
            max_tokens=payload.get("max_tokens"),
            run_token_budget=payload.get("run_token_budget"),
            on_progress=on_progress, on_lifecycle=on_lifecycle,
            policy=policy, enforce_policy=bool(payload.get("enforce_policy", False)),
            continue_on_policy_deny=bool(payload.get("continue_on_policy_deny", True)),
            policy_target=payload.get("policy_target"),
            activity_routes=payload.get("activity_routes") or {},
            seed=payload.get("seed"), run_id=payload.get("run_id"),
            scenario=payload.get("scenario"), goal=payload.get("goal") or {},
            on_invocation=on_invocation, runtime="container",
            available_tools=available_command_tools,
            tool_executor=tool_runner.run,
        )

        from ranger.agent.runtime import get_model_usage_summary
        command_metadata = {
            "command_tools_requested": list(command_profile.get("command_tools", [])),
            "command_tools_available": available_command_tools,
            "command_tools_used": sorted(used_tools),
            "tool_calls": tool_calls,
        }
        (run_dir / "command-tools.json").write_text(json.dumps(command_metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        outcome = {**outcome, "usage": get_model_usage_summary(), **command_metadata}
        outcome_path.write_text(json.dumps(outcome, ensure_ascii=False, default=str), encoding="utf-8")
        return 0
    except Exception as exc:
        error_path.write_text(traceback.format_exc(), encoding="utf-8")
        try:
            outcome_path.write_text(json.dumps({
                "reason": "container_episode_error", "step": None,
                "detail": f"{type(exc).__name__}: {exc}",
            }), encoding="utf-8")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())