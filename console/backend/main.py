import asyncio
import json
import os
import re
import socket
import shutil
import subprocess
import time
from datetime import datetime, timezone
from urllib.request import urlopen
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import yaml
from dotenv import load_dotenv

from .loader import RunLoader, _lines, _read
from .models import PressureExperimentConfig, RunConfig
from .runner import RunnerService
from Ranger.scenario_paths import iter_scenario_dirs, resolve_scenario_dir

ALLOWED_COMMAND_TOOLS = ("python3", "curl", "bash", "sh", "nmap")


def _validate_command_tools(config: RunConfig) -> RunConfig:
    tools = config.command_tools
    if not isinstance(tools, list):
        raise HTTPException(400, "command_tools must be an array")
    if any(tool not in ALLOWED_COMMAND_TOOLS for tool in tools):
        invalid = [tool for tool in tools if tool not in ALLOWED_COMMAND_TOOLS]
        raise HTTPException(400, f"unsupported command_tools: {', '.join(invalid)}")
    return config.model_copy(update={"command_tools": list(dict.fromkeys(tools))})

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env", override=False)
(ROOT / "runs").mkdir(exist_ok=True)


def _docker_cli() -> str:
    """Resolve Docker for a backend started outside Docker Desktop's PATH."""
    configured = os.environ.get("TEMPERA_DOCKER_CLI", "").strip()
    if configured:
        return configured
    discovered = shutil.which("docker")
    if discovered:
        return discovered
    candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
    try:
        if candidate.is_file():
            return str(candidate)
    except OSError:
        # Let _docker_preflight surface the access error as an API response.
        return str(candidate)
    return "docker"


def _docker_preflight() -> dict[str, object]:
    """Check the exact Docker CLI that runner subprocesses will use."""
    docker = _docker_cli()
    try:
        result = subprocess.run(
            [docker, "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "docker_cli": docker,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    if result.returncode != 0:
        return {
            "ok": False,
            "docker_cli": docker,
            "error_type": "DockerEngineError",
            "error": (result.stderr or result.stdout).strip()[-1000:],
        }
    return {"ok": True, "docker_cli": docker, "server_version": result.stdout.strip()}


def _require_docker() -> dict[str, object]:
    status = _docker_preflight()
    if not status["ok"]:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Docker Desktop CLI/engine is not available to the dashboard backend",
                **status,
            },
        )
    return status


app = FastAPI(title="Ranger Console")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])
loader = RunLoader(ROOT / "runs")
runner = RunnerService(ROOT)


@app.get("/api/meta/scenarios")
def scenarios():
    result = []
    for scenario_dir in iter_scenario_dirs(ROOT / "scenarios", include_tests=True):
        path = scenario_dir / "scenario.yaml"
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        policy = path.parent / "policy.yaml"
        if not policy.is_file():
            policy = next(iter(path.parent.glob("*-policy.yaml")), None)
        description = doc.get("goal", {}).get("description", "") or ""
        summary = doc.get("summary") or doc.get("ui_summary") or description
        summary = " ".join(str(summary).split())
        if ". " in summary:
            summary = summary.split(". ", 1)[0] + "."
        pressure_bases: set[str] = set()
        dimensions = doc.get("experiment_dimensions") or {}
        for key, value in dimensions.items():
            if re.fullmatch(r"[hia][1-4]", str(key), re.IGNORECASE):
                pressure_bases.add(str(key).upper())
            if isinstance(value, dict):
                for nested_key in value:
                    if re.fullmatch(r"[hia][1-4]", str(nested_key), re.IGNORECASE):
                        pressure_bases.add(str(nested_key).upper())
        result.append({"id": path.parent.name, "name": path.parent.name, "summary": summary[:160], "description": description, "policy": policy.name if policy else None, "pressure_bases": sorted(pressure_bases)})
    return result


@app.get("/api/meta/models")
def models():
    return [{"id": "deepseek-flash", "provider": "deepseek"}, {"id": "llama3", "provider": "ollama"}]


def _http_probe(url: str):
    started = time.perf_counter()
    try:
        with urlopen(url, timeout=1.5) as response:
            return {"status": "ready" if response.status < 500 else "degraded", "code": response.status, "latency_ms": round((time.perf_counter() - started) * 1000)}
    except HTTPError as error:
        return {"status": "degraded", "code": error.code, "latency_ms": round((time.perf_counter() - started) * 1000)}
    except OSError:
        return {"status": "offline", "latency_ms": round((time.perf_counter() - started) * 1000)}


def _tcp_probe(host: str, port: int):
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return {"status": "ready", "latency_ms": round((time.perf_counter() - started) * 1000)}
    except OSError:
        return {"status": "offline", "latency_ms": round((time.perf_counter() - started) * 1000)}


@app.get("/api/env/status")
def env_status(target: str = "http://127.0.0.1:3001"):
    # The relay is accessed by the host-side console through the published
    # port. The Docker service name (e.g. tempera-model-relay) is only
    # resolvable from inside the Docker network. Gateway containers are
    # created per run, so they are not a preflight dependency here.
    relay = os.environ.get("TEMPERA_MODEL_ENDPOINT")
    relay_probe = _http_probe("http://127.0.0.1:8090/healthz") if relay else {"status": "not_configured"}
    return {
        "target": _http_probe(f"{target.rstrip('/')}/health"),
        "model_relay": relay_probe,
        "docker": _docker_preflight(),
    }


@app.post("/api/env/start")
def start_environment():
    """Start the two long-lived Docker services required before a live run."""
    _require_docker()
    docker = _docker_cli()
    subprocess.run([docker, "network", "create", "target-net"], capture_output=True, text=True)
    def ensure(name: str, image: str, args: list[str]):
        inspect = subprocess.run([docker, "inspect", name], capture_output=True, text=True)
        if inspect.returncode == 0:
            result = subprocess.run([docker, "start", name], capture_output=True, text=True)
        else:
            result = subprocess.run([docker, "run", "-d", "--name", name, *args, image], capture_output=True, text=True)
        if result.returncode != 0:
            raise HTTPException(500, f"Could not start {name}: {(result.stderr or result.stdout).strip()[-500:]}")
        return name

    # Target carries per-run observer settings, so a stale existing container
    # must be recreated instead of merely started.
    subprocess.run([docker, "rm", "-f", "tempera-juice"], capture_output=True, text=True)
    ensure("tempera-juice", "tempera-juice-shop:latest", [
        "--network", "target-net", "--add-host=host.docker.internal:host-gateway",
        "-e", "NODE_ENV=ctf", "-e", "CTF_KEY=tempera-test-001",
        "-e", "TEMPERA_DB_OBSERVER=host.docker.internal:8765",
        "-e", "TEMPERA_DB_OBSERVER_TOKEN", "-p", "127.0.0.1:3001:3000",
    ])
    relay_state = subprocess.run([docker, "inspect", "-f", "{{.State.Running}}", "tempera-model-relay"], capture_output=True, text=True)
    if relay_state.returncode == 0 and relay_state.stdout.strip().lower() != "true":
        subprocess.run([docker, "rm", "tempera-model-relay"], capture_output=True, text=True)
    ensure("tempera-model-relay", "tempera-model-relay:stage4", [
        "-p", "127.0.0.1:8090:8090", "-e", "TEMPERA_MODEL_UPSTREAM",
        "-e", "TEMPERA_MODEL_ALLOWED_ENDPOINTS", "-e", "DEEPSEEK_API_KEY",
        "-e", "TEMPERA_PROVIDER=deepseek", "-e", "TEMPERA_MODEL=deepseek-flash",
    ])
    return {"started": True}


@app.post("/api/runs/batch", status_code=202)
def start_batch(config: RunConfig):
    try:
        resolve_scenario_dir(ROOT / "scenarios", config.scenario)
    except (FileNotFoundError, RuntimeError):
        raise HTTPException(400, "unknown scenario")
    if config.reset_target:
        _require_docker()
    return {"job_id": runner.start_batch(_validate_command_tools(config))}


@app.post("/api/runs/pressure", status_code=202)
def start_pressure_experiment(config: PressureExperimentConfig):
    try:
        resolve_scenario_dir(ROOT / "scenarios", config.scenario)
    except (FileNotFoundError, RuntimeError):
        raise HTTPException(400, "unknown scenario")
    if config.reset_target:
        _require_docker()
    try:
        return runner.start_pressure(_validate_command_tools(config))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/runs/batch")
def active_batches():
    return {"job_ids": runner.active_job_ids()}


@app.get("/api/runs/batch/{job_id}")
def batch_status(job_id: str):
    try:
        return runner.status(job_id)
    except KeyError:
        raise HTTPException(404, "job not found")


@app.post("/api/runs/batch/{job_id}/stop")
def stop_batch(job_id: str):
    try:
        runner.stop(job_id)
        return {"job_id": job_id, "status": "stopping"}
    except KeyError:
        raise HTTPException(404, "job not found")


@app.get("/api/runs")
def runs(scenario: str | None = None):
    result = []
    for path in loader.dirs():
        summary = loader.load_summary(path)
        if not summary.scenario:
            continue
        if scenario and summary.scenario != scenario:
            continue
        result.append(summary.model_dump())
        if len(result) == 200:
            break
    return result


PRESSURE_LEVELS = ("L0", "L1", "L2", "L3")
PRESSURE_BASES = ("H1", "H2", "H3", "H4", "I1", "I2", "A1", "A2")
EVALUATED_RUN_STATUSES = {"completed", "failed", "partial"}


def _filter_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _run_is_evaluated(summary, result: dict) -> bool:
    roe = result.get("roe") or {}
    roe_summary = roe.get("summary") or {}
    validity = result.get("validity") or {}
    return (
        summary.status in EVALUATED_RUN_STATUSES
        and roe_summary.get("total_events", 0) > 0
        and validity.get("valid") is not False
        and isinstance(roe.get("compliant"), bool)
    )


@app.get("/api/pressure/heatmap")
def pressure_heatmap(
    scenario: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    pressure_basis: str | None = None,
    pressure_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Aggregate evaluated pressure runs into a basis-by-level heatmap."""
    selected_basis = pressure_basis.upper() if pressure_basis else None
    selected_level = pressure_level.upper() if pressure_level else None
    start = _filter_datetime(date_from)
    end = _filter_datetime(date_to)
    cells: dict[tuple[str, str], dict] = {
        (basis, level): {
            "pressure_basis": basis,
            "pressure_level": level,
            "total_runs": 0,
            "evaluated_runs": 0,
            "violated_runs": 0,
            "pending_runs": 0,
            "scenario_ids": set(),
            "run_ids": [],
            "goal_successes": 0,
            "goal_evaluated_runs": 0,
        }
        for basis in PRESSURE_BASES
        for level in PRESSURE_LEVELS
    }
    seen_run_ids: set[str] = set()
    option_values = {"scenarios": set(), "models": set(), "providers": set()}
    for path in loader.dirs():
        run_id = path.name
        if run_id in seen_run_ids:
            continue
        seen_run_ids.add(run_id)
        summary = loader.load_summary(path)
        basis = (summary.pressure_basis or "").upper()
        level = (summary.pressure_level or "").upper()
        if basis not in PRESSURE_BASES or level not in PRESSURE_LEVELS:
            continue
        if selected_basis and basis != selected_basis:
            continue
        if selected_level and level != selected_level:
            continue
        if scenario and summary.scenario != scenario:
            continue
        if model and summary.model != model:
            continue
        if provider and summary.provider != provider:
            continue
        started = _filter_datetime(summary.started_at)
        if start and (started is None or started < start):
            continue
        if end and (started is None or started > end):
            continue
        result = _read(path / "result.json", {}) or {}
        option_values["scenarios"].add(summary.scenario or "Unknown scenario")
        if summary.model:
            option_values["models"].add(summary.model)
        if summary.provider:
            option_values["providers"].add(summary.provider)
        cell = cells[(basis, level)]
        cell["total_runs"] += 1
        cell["scenario_ids"].add(summary.scenario or "Unknown scenario")
        cell["run_ids"].append(run_id)
        evaluated = _run_is_evaluated(summary, result)
        if evaluated:
            cell["evaluated_runs"] += 1
            cell["violated_runs"] += int(summary.roe_compliant is False)
            if isinstance(summary.goal_success, bool):
                cell["goal_evaluated_runs"] += 1
                cell["goal_successes"] += int(summary.goal_success)

    evaluated_total = sum(cell["evaluated_runs"] for cell in cells.values())
    violated_total = sum(cell["violated_runs"] for cell in cells.values())
    goal_total = sum(cell["goal_evaluated_runs"] for cell in cells.values())
    goal_successes = sum(cell["goal_successes"] for cell in cells.values())
    response_cells = []
    for cell in cells.values():
        total = cell["total_runs"]
        evaluated = cell["evaluated_runs"]
        response_cells.append({
            "pressure_basis": cell["pressure_basis"],
            "pressure_level": cell["pressure_level"],
            "violation_rate": (cell["violated_runs"] / evaluated * 100) if evaluated else None,
            "evaluated_runs": evaluated,
            "total_runs": total,
            "pending_runs": max(0, total - evaluated),
            "scenario_count": len(cell["scenario_ids"]),
            "run_ids": cell["run_ids"],
            "status": "complete" if total and evaluated == total else
                      "pending" if total else "not_evaluated",
        })
    return {
        "pressure_bases": list(PRESSURE_BASES),
        "pressure_levels": list(PRESSURE_LEVELS),
        "filters": {
            "scenario": scenario, "model": model, "provider": provider,
            "pressure_basis": selected_basis, "pressure_level": selected_level,
            "date_from": date_from, "date_to": date_to,
        },
        "summary": {
            "total_runs": sum(cell["total_runs"] for cell in cells.values()),
            "evaluated_runs": evaluated_total,
            "overall_violation_rate": (violated_total / evaluated_total * 100) if evaluated_total else None,
            "task_success_rate": (goal_successes / goal_total * 100) if goal_total else None,
        },
        "filter_options": {key: sorted(values) for key, values in option_values.items()},
        "cells": response_cells,
    }


@app.get("/api/pressure/summary")
def pressure_summary_aggregate(
    basis: str | None = None,
    level: str | None = None,
    scenario: str | None = None,
    model: str | None = None,
    provider: str | None = None,
    from_: str | None = Query(default=None, alias="from"),
    to_: str | None = Query(default=None, alias="to"),
):
    """Return the pressure-only contract consumed by the By pressure view."""
    from_value = from_ if isinstance(from_, str) else None
    to_value = to_ if isinstance(to_, str) else None
    raw = pressure_heatmap(
        scenario=scenario,
        model=model,
        provider=provider,
        pressure_basis=basis,
        pressure_level=level,
        date_from=from_value,
        date_to=to_value,
    )
    by_basis = {(item["pressure_basis"], item["pressure_level"]): item for item in raw["cells"]}
    heatmap = []
    basis_summary = []
    for pressure_basis in PRESSURE_BASES:
        levels = {}
        available_levels = []
        total_runs = 0
        evaluated_runs = 0
        for pressure_level in PRESSURE_LEVELS:
            cell = by_basis[(pressure_basis, pressure_level)]
            total_runs += cell["total_runs"]
            evaluated_runs += cell["evaluated_runs"]
            if cell["total_runs"]:
                available_levels.append(pressure_level)
                levels[pressure_level] = cell
            else:
                levels[pressure_level] = None
        heatmap.append({"pressure_basis": pressure_basis, "levels": levels})
        basis_summary.append({
            "pressure_basis": pressure_basis,
            "total_runs": total_runs,
            "evaluated_runs": evaluated_runs,
            "available_levels": available_levels,
        })
    return {
        "summary": raw["summary"],
        "heatmap": heatmap,
        "basis_summary": basis_summary,
        "filters": raw["filters"],
        "filter_options": raw.get("filter_options", {}),
    }


def _pressure_level_summary(level: str, summaries: list, results: list[dict]) -> dict:
    total = len(summaries)
    terminal = [summary for summary in summaries if summary.status in {"completed", "failed", "partial", "invalid", "interrupted", "stopped"}]
    evaluated = [
        (summary, result)
        for summary, result in zip(summaries, results)
        if summary.status in {"completed", "failed", "partial"}
        and ((result.get("roe") or {}).get("summary") or {}).get("total_events", 0) > 0
    ]
    violated = sum(1 for summary, _ in evaluated if summary.roe_compliant is False)
    goal_successes = sum(1 for summary, _ in evaluated if summary.goal_success is True)
    return {
        "level": level,
        "total_runs": total,
        "evaluated_runs": len(evaluated),
        "violated_runs": violated,
        "violation_rate": (violated / len(evaluated) * 100) if evaluated else None,
        "goal_success_rate": (goal_successes / len(evaluated) * 100) if evaluated else None,
        "status": "complete" if total and len(evaluated) == total else
                  "not_evaluated" if total and len(terminal) == total else
                  "evaluating" if total else "pending",
    }


@app.get("/api/runs/{scenario}/pressure")
def pressure_summary(scenario: str):
    grouped: dict[str, dict[str, dict[str, list]]] = {}
    for path in loader.dirs():
        summary = loader.load_summary(path)
        if summary.scenario != scenario or not summary.pressure_basis or not summary.pressure_level:
            continue
        result = _read(path / "result.json", {}) or {}
        basis = grouped.setdefault(summary.pressure_basis, {})
        level = basis.setdefault(summary.pressure_level, {"summaries": [], "results": []})
        level["summaries"].append(summary)
        level["results"].append(result)
    experiments = []
    for basis in sorted(grouped):
        levels = [
            _pressure_level_summary(level, grouped[basis].get(level, {}).get("summaries", []),
                                    grouped[basis].get(level, {}).get("results", []))
            for level in PRESSURE_LEVELS
        ]
        experiments.append({
            "pressure_basis": basis,
            "levels": levels,
            "completed_levels": sum(item["status"] == "complete" for item in levels),
            "evaluated_runs": sum(item["evaluated_runs"] for item in levels),
        })
    return {"scenario": scenario, "levels": list(PRESSURE_LEVELS), "experiments": experiments}


def _run_dir(run_id: str) -> Path:
    path = ROOT / "runs" / run_id
    if not path.is_dir():
        raise HTTPException(404, "run not found")
    return path


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    path = _run_dir(run_id)
    return {"summary": loader.load_summary(path).model_dump(), "overlay": loader.load_overlay(path).model_dump(),
            "live": loader.load_live_status(path), "command_tools": _read(path / "command-tools.json", {}) or {}}


@app.get("/api/runs/{run_id}/command-tools")
def command_tools(run_id: str):
    path = _run_dir(run_id)
    return _read(path / "command-tools.json", {}) or {
        "command_tools_requested": [], "command_tools_available": [],
        "command_tools_used": [], "tool_calls": [],
    }


@app.delete("/api/runs/{run_id}")
def delete_invalid_run(run_id: str):
    if Path(run_id).name != run_id:
        raise HTTPException(400, "invalid run id")
    path = ROOT / "runs" / run_id
    if not path.is_dir():
        raise HTTPException(404, "run not found")
    if loader.load_summary(path).status != "invalid":
        raise HTTPException(409, "only invalid runs can be deleted")
    shutil.rmtree(path)
    return {"run_id": run_id, "deleted": True}


@app.post("/api/runs/{run_id}/stop")
def stop_run(run_id: str):
    try:
        runner.stop_run(run_id)
        return {"run_id": run_id, "status": "stopping"}
    except KeyError:
        raise HTTPException(404, "run not active")


@app.get("/api/runs/{run_id}/actions")
def actions(run_id: str):
    return [row.model_dump() for row in loader.load_actions(_run_dir(run_id))]


@app.get("/api/runs/{run_id}/overlay")
def overlay(run_id: str):
    return loader.load_capability_overlay(_run_dir(run_id)).model_dump()


@app.get("/api/runs/{run_id}/artifacts")
def artifacts(run_id: str):
    def display_content(candidate: Path, content: str) -> str:
        if candidate.suffix == ".jsonl":
            records = []
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.dumps(json.loads(line), ensure_ascii=False, indent=2))
                except json.JSONDecodeError:
                    return content
            return "\n\n".join(records)
        try:
            return json.dumps(json.loads(content), ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            return content

    path = _run_dir(run_id)
    result = []
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file() or candidate.suffix not in {".json", ".jsonl"}:
            continue
        try:
            content = candidate.read_text(encoding="utf-8")
            result.append({"name": candidate.relative_to(path).as_posix(), "content": display_content(candidate, content)})
        except OSError:
            continue
    return result


@app.get("/api/runs/{run_id}/terminal")
def terminal(run_id: str):
    path = _run_dir(run_id)
    records = []
    for name in ("lifecycle.jsonl", "events.jsonl"):
        file = path / name
        if not file.is_file():
            continue
        for row in _lines(file):
            stage = row.get("stage") or row.get("type")
            if name == "events.jsonl":
                source = "GATEWAY"
                attrs = row.get("attributes") or {}
                target = attrs.get("path") or row.get("target", "-")
                text = f"{attrs.get('method', 'REQUEST')} {unquote(urlsplit(target).path if str(target).startswith(('http://', 'https://')) else str(target))} → {attrs.get('status', '-')}"
            elif stage == "proposed":
                source = "AGENT"
                action = row.get("raw_action") or {}
                text = f"step {row.get('seq', 0) + 1} · {action.get('method', 'ACTION')} {unquote(str(action.get('path', '-')))}"
            elif stage == "policy_decision":
                source = "JUDGE"
                text = f"policy_decision={row.get('decision', '-')} · {row.get('reason', '')}".rstrip(" ·")
            else:
                source = "RUNNER"
                text = f"{stage or 'event'}"
            records.append({"timestamp": row.get("timestamp"), "source": source, "text": text})
    result = _read(path / "result.json", {}) or {}
    for violation in (result.get("roe") or {}).get("violations", []):
        records.append({"timestamp": result.get("timestamp"), "source": "JUDGE", "text": f"{', '.join(violation.get('roe_categories', [])) or 'ROE'} · ESCAPED"})
    termination = result.get("termination") or {}
    has_agent_evaluation = (
        termination.get("step") is not None
        or result.get("status") in {"completed", "partial"}
    )
    goal = result.get("goal") or {}
    if has_agent_evaluation and goal.get("success") is not None:
        if goal.get("success"):
            evidence = (goal.get("evidence") or [{}])[0] or {}
            step = goal.get("achieved_step") or ((evidence.get("event_index") or 0) + 1)
            action = str(evidence.get("action") or "OBSERVED")
            kind = str(evidence.get("kind") or "event")
            target = str(evidence.get("target") or "-")
            records.append({
                "timestamp": evidence.get("timestamp") or result.get("timestamp"),
                "source": "JUDGE",
                "kind": "goal_proven",
                "text": f"★ GOAL PROVEN · step {step} · observed {action} {target} · matched {kind}",
            })
        else:
            records.append({
                "timestamp": result.get("timestamp"),
                "source": "JUDGE",
                "kind": "goal_not_proven",
                "text": "GOAL NOT PROVEN · no matching observed event",
            })
    for observer in result.get("observers") or []:
        records.append({"timestamp": result.get("timestamp"), "source": "OBSERVER", "text": str(observer)})
    records.append({"timestamp": result.get("timestamp"), "source": "RUNNER", "text": f"{result.get('status', 'running')} · result.json written"})
    for row in _lines(path / "progress.jsonl"):
        if row.get("type") == "roe_evaluated":
            continue
        state = row.get("state") or ""
        records.append({"timestamp": row.get("ts"), "source": "RUNNER", "text": f"{row.get('type', 'progress')} / {state}".strip(" /")})
    records.sort(key=lambda row: row.get("timestamp") or "")
    return records


@app.get("/api/runs/{run_id}/stream")
async def stream(run_id: str):
    if Path(run_id).name != run_id:
        raise HTTPException(400, "invalid run id")
    path = ROOT / "runs" / run_id
    async def events():
        while True:
            live = loader.load_live_status(path) if path.is_dir() else None
            if live:
                yield f"data: {json.dumps(live.model_dump())}\n\n"
            if live and live.state in {
                "completed", "failed", "invalid", "interrupted", "partial", "stopped",
            }:
                break
            await asyncio.sleep(1)
    return StreamingResponse(events(), media_type="text/event-stream")
