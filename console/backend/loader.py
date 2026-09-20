import json
from datetime import datetime
from pathlib import Path

from .models import ActionRow, LiveStatus, Overlay, RunSummary


def _read(path: Path | None, default=None):
    if path is None:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _lines(path: Path | None):
    if path is None:
        return []
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError):
        return []


def _manifest_paths(run_dir: Path) -> dict:
    """manifest.json -> artifact path map; missing manifests degrade gracefully."""
    manifest = _read(run_dir / "manifest.json", {}) or {}
    artifacts = manifest.get("artifacts", {})
    return {key: run_dir / value["path"] for key, value in artifacts.items() if "path" in value}


def _art(paths: dict, key: str, fallback: str) -> Path | None:
    """Prefer a manifest artifact path, then the legacy filename fallback."""
    return paths.get(key) or paths.get(fallback)


class RunLoader:
    def __init__(self, runs_dir: Path):
        self.runs_dir = Path(runs_dir)

    def dirs(self):
        return sorted((p for p in self.runs_dir.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)

    def load_summary(self, run_dir: Path) -> RunSummary:
        paths = _manifest_paths(run_dir)
        config = _read(_art(paths, "config", "config.json") or run_dir / "config.json", {}) or {}
        result = _read(_art(paths, "result", "result.json") or run_dir / "result.json", {}) or {}
        status = _read(_art(paths, "status", "status.json") or run_dir / "status.json", {}) or {}
        roe = result.get("roe", {})
        categories = roe.get("categories", {})
        violations = sum(1 for item in categories.values() if item.get("status") == "violation")
        started = config.get("started_at") or status.get("started_at")
        ended = result.get("finished_at") or result.get("ended_at")
        duration = None
        if started and ended:
            try:
                duration = (datetime.fromisoformat(ended.replace("Z", "+00:00")) - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds()
            except ValueError:
                pass
        return RunSummary(run_id=run_dir.name, scenario=config.get("scenario"), model=config.get("model"), provider=config.get("provider"),
                          status=result.get("status") or status.get("execution", {}).get("status") or "running",
                          goal_success=result.get("goal", {}).get("success"), roe_compliant=roe.get("compliant"), violation_count=violations,
                          steps=result.get("metrics", {}).get("steps") or status.get("agent", {}).get("current_step") or 0,
                          tokens_total=result.get("usage", {}).get("total_tokens"), duration_sec=duration, started_at=started,
                          termination_reason=result.get("termination", {}).get("reason"))

    def load_live_status(self, run_dir: Path) -> LiveStatus | None:
        paths = _manifest_paths(run_dir)
        status = _read(_art(paths, "status", "status.json") or run_dir / "status.json")
        if not status:
            return None
        agent, progress = status.get("agent", {}), status.get("progress", {})
        started = status.get("started_at")
        elapsed = None
        if started:
            try:
                elapsed = max(0, (datetime.now().astimezone() - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds())
            except ValueError:
                pass
        return LiveStatus(run_id=run_dir.name, state=status.get("state", "unknown"), step=agent.get("current_step"), max_steps=agent.get("max_steps"),
                          goal_observed=bool(progress.get("goal_observed")), roe_violation_observed=bool(progress.get("roe_violation_observed")),
                          updated_at=status.get("updated_at"), elapsed_sec=elapsed)

    def load_actions(self, run_dir: Path) -> list[ActionRow]:
        paths = _manifest_paths(run_dir)
        lifecycle = _lines(_art(paths, "lifecycle", "lifecycle.jsonl") or run_dir / "lifecycle.jsonl")
        traces = {item.get("step"): item for item in _lines(_art(paths, "trace", "trace.jsonl") or run_dir / "trace.jsonl")}
        rows = []
        for item in lifecycle:
            if item.get("stage") not in {"proposed", "executed", "observed"}:
                continue
            normalized = item.get("normalized_action") or {}
            target = normalized.get("resource") or {}
            rows.append(ActionRow(seq=item.get("seq", 0), action_id=item.get("action_id", ""), phase=item.get("stage"),
                                  thought=traces.get((item.get("reference") or {}).get("action_step"), {}).get("thought"),
                                  method=normalized.get("method"), path=target if isinstance(target, str) else target.get("path"),
                                  roe_status="blocked" if item.get("decision") == "deny" else "allowed"))
        return rows

    def load_overlay(self, run_dir: Path) -> Overlay:
        paths = _manifest_paths(run_dir)
        result = _read(_art(paths, "result", "result.json") or run_dir / "result.json", {}) or {}
        progress = result.get("progress", {}) or {}
        roe = result.get("roe", {}) or {}
        return Overlay(phases=progress.get("completed_stages", []),
                       goal_marker={"seq": result.get("goal", {}).get("achieved_step"), "achieved_step": result.get("goal", {}).get("achieved_step")} if result.get("goal", {}).get("success") else None,
                       roe_violations=[{"category": key, **value} for key, value in roe.get("categories", {}).items() if value.get("status") == "violation"])