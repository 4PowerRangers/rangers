import json
from datetime import datetime
from pathlib import Path

from .models import ActionRow, CapabilityOverlay, CapabilityStage, LiveStatus, Overlay, RunSummary


def _read(path: Path | None, default=None):
    if path is None:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _format_last_action(agent: dict) -> str | None:
    data = agent.get("last_action") or {}
    if data.get("method") and data.get("path"):
        text = f"{data['method']} {data['path']}"
        if data.get("status_code"):
            text += f" -> {data['status_code']}"
        return text
    if data.get("action"):
        return str(data["action"])
    return None


def _lines(path: Path | None):
    if path is None:
        return []
    try:
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows
    except OSError:
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
        if not self.runs_dir.is_dir():
            return []
        return sorted((p for p in self.runs_dir.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)

    def load_summary(self, run_dir: Path) -> RunSummary:
        paths = _manifest_paths(run_dir)
        config = _read(_art(paths, "config", "config.json") or run_dir / "config.json", {}) or {}
        result = _read(_art(paths, "result", "result.json") or run_dir / "result.json", {}) or {}
        status = _read(_art(paths, "status", "status.json") or run_dir / "status.json", {}) or {}
        lifecycle = _lines(_art(paths, "lifecycle", "lifecycle.jsonl") or run_dir / "lifecycle.jsonl")
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
        logged_steps = [
            item.get("step") or item.get("current_step")
            for item in lifecycle
            if isinstance(item.get("step") or item.get("current_step"), (int, float))
        ]
        executed_steps = sum(1 for item in lifecycle if item.get("phase") == "executed")
        termination_step = (result.get("termination") or {}).get("step")
        event_steps = [
            item.get("reference", {}).get("action_step")
            for item in _lines(_art(paths, "events", "events.jsonl") or run_dir / "events.jsonl")
            if isinstance((item.get("reference") or {}).get("action_step"), (int, float))
        ]
        steps = result.get("metrics", {}).get("steps") or status.get("agent", {}).get("current_step") or termination_step or (max(event_steps) if event_steps else None) or (max(logged_steps) if logged_steps else executed_steps) or 0
        raw_status = result.get("status") or status.get("execution", {}).get("status") or "running"
        if raw_status == "completed" and result.get("goal", {}).get("success") is False:
            raw_status = "failed"
        return RunSummary(run_id=run_dir.name, lab_version=config.get("lab_version", "v1"), scenario=config.get("scenario"), model=config.get("model"), provider=config.get("provider"),
                          status=raw_status,
                          goal_success=result.get("goal", {}).get("success"), goal_step=result.get("goal", {}).get("achieved_step"), roe_compliant=roe.get("compliant"), violation_count=violations,
                          roe_categories=categories,
                          steps=steps,
                          max_steps=config.get("max_steps") or status.get("agent", {}).get("max_steps"),
                          tokens_total=result.get("usage", {}).get("total_tokens"), duration_sec=duration, started_at=started,
                          termination_reason=result.get("termination", {}).get("reason"),
                          last_action=_format_last_action(status.get("agent", {})),
                          pressure_basis=config.get("pressure_basis"),
                          pressure_level=config.get("pressure_level"),
                          pressure_experiment_id=config.get("pressure_experiment_id"),
                          command_tools=config.get("command_tools", []))

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
                execution_status = (status.get("execution") or {}).get("status")
                terminal = execution_status in {"completed", "failed", "stopped", "interrupted"}
                ended = status.get("updated_at") if terminal else None
                end_time = datetime.fromisoformat(ended.replace("Z", "+00:00")) if ended else datetime.now().astimezone()
                elapsed = max(0, (end_time - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds())
            except ValueError:
                pass
        return LiveStatus(run_id=run_dir.name, scenario=status.get("scenario"), state=status.get("state", "unknown"), step=agent.get("current_step"), max_steps=agent.get("max_steps"),
                          goal_observed=bool(progress.get("goal_observed")), goal_step=agent.get("current_step") if progress.get("goal_observed") else None, roe_violation_observed=bool(progress.get("roe_violation_observed")),
                          updated_at=status.get("updated_at"), elapsed_sec=elapsed, last_action=_format_last_action(agent))

    def load_actions(self, run_dir: Path) -> list[ActionRow]:
        paths = _manifest_paths(run_dir)
        result = _read(_art(paths, "result", "result.json") or run_dir / "result.json", {}) or {}
        violations_by_action = {}
        unclassified_by_action = set()
        for violation in (result.get("roe") or {}).get("violations", []):
            action_id = (violation.get("evidence") or {}).get("action_id") or ((violation.get("event_key") or [None, None, None])[2])
            if violation.get("severity", "violation") == "unclassified":
                if action_id:
                    unclassified_by_action.add(action_id)
                continue
            if violation.get("severity", "violation") != "violation":
                continue
            if action_id:
                entry = violations_by_action.setdefault(action_id, {"roe_status": "escaped", "roe_dimension": violation.get("dimension"), "roe_categories": []})
                entry["roe_categories"].extend(c for c in violation.get("roe_categories") or [] if c not in entry["roe_categories"])
        live_roe_by_action = {}
        for item in _lines(_art(paths, "progress", "progress.jsonl") or run_dir / "progress.jsonl"):
            if item.get("type") != "roe_evaluated":
                continue
            for verdict in (item.get("detail") or {}).get("verdicts") or []:
                action_id = verdict.get("action_id")
                if action_id:
                    live_roe_by_action[action_id] = verdict
        lifecycle = _lines(_art(paths, "lifecycle", "lifecycle.jsonl") or run_dir / "lifecycle.jsonl")
        events = {}
        config = _read(_art(paths, "config", "config.json") or run_dir / "config.json", {}) or {}
        target_config = config.get("target") or {}
        base_url = config.get("upstream") or (target_config.get("base_url") if isinstance(target_config, dict) else None) or ""
        for record in _lines(_art(paths, "events", "events.jsonl") or run_dir / "events.jsonl"):
            attributes = record.get("attributes") or {}
            target = record.get("target", "")
            events[record.get("action_id") or attributes.get("action_id") or f"action-{record.get('seq', 0) + 1}"] = {
                "method": attributes.get("method") or record.get("method"),
                "path": attributes.get("path") or record.get("path") or (target.replace(base_url, "") if isinstance(target, str) else None),
                "status_code": attributes.get("status") or record.get("status_code"),
                "seq": record.get("seq"),
            }

        action_meta = {}
        visible_action_ids = set(events)
        for item in lifecycle:
            action_id = item.get("action_id")
            if not action_id:
                continue
            phase = item.get("phase") or item.get("stage")
            meta = action_meta.setdefault(action_id, {
                "seq": item.get("seq", 0), "phase": None, "thought": None,
                "path": None, "decision": None, "decision_reason": None,
                "roe_status": None, "roe_dimension": None,
                "roe_category": None, "roe_categories": [], "raw_action": {},
            })
            normalized = item.get("normalized_action") or {}
            raw_action = item.get("raw_action") or {}
            if isinstance(raw_action, dict):
                meta["raw_action"] = raw_action
            meta["thought"] = raw_action.get("thought") or item.get("thought") or meta["thought"]
            meta["path"] = item.get("path") or normalized.get("resource") or raw_action.get("path") or meta["path"]
            if phase in {"observed", "executed"}:
                visible_action_ids.add(action_id)
                meta["phase"] = phase
            if phase == "executed":
                meta["phase"] = "executed"
            if phase == "policy_decision":
                decision = item.get("decision") or {}
                meta["decision_reason"] = item.get("reason")
                if isinstance(decision, dict):
                    gate_decision = decision.get("decision")
                    is_blocked = decision.get("blocked") is True or gate_decision == "deny"
                    meta["decision"] = "blocked" if is_blocked else "allowed"
                    if is_blocked:
                        meta["phase"] = "policy_decision"
                        visible_action_ids.add(action_id)
                elif decision == "deny":
                    meta["decision"] = "blocked"
                    meta["phase"] = "policy_decision"
                    visible_action_ids.add(action_id)
                elif decision == "allow":
                    meta["decision"] = "allowed"
                if item.get("label") == "goal":
                    meta["roe_status"] = "goal"

        actions = {
            action_id: ActionRow(
                seq=events.get(action_id, {}).get("seq", meta.get("seq", 0)),
                action_id=action_id,
                phase=meta.get("phase"),
                thought=meta.get("thought"),
                path=events.get(action_id, {}).get("path") or meta.get("path"),
                method=events.get(action_id, {}).get("method"),
                status_code=events.get(action_id, {}).get("status_code"),
                decision=meta.get("decision"),
                decision_reason=meta.get("decision_reason"),
                roe_status=meta.get("roe_status"),
                roe_dimension=meta.get("roe_dimension"),
                roe_category=meta.get("roe_category"),
                roe_categories=list(meta.get("roe_categories", [])),
                raw_action=meta.get("raw_action") or {},
            )
            for action_id in visible_action_ids
            for meta in [action_meta.get(action_id, {})]
        }

        calls = sorted((result.get("usage") or {}).get("calls") or [], key=lambda c: c.get("index", 0))
        ordered_rows = sorted(actions.values(), key=lambda row: row.seq)
        for row, call in zip(ordered_rows, calls):
            row.prompt_tokens = call.get("prompt_tokens")
            row.completion_tokens = call.get("completion_tokens")
            row.total_tokens = call.get("total_tokens")

        for action_id, row in actions.items():
            event = events.get(action_id, {})
            row.method = event.get("method")
            row.status_code = event.get("status_code")
            if not row.path:
                row.path = event.get("path")
            if event.get("seq") is not None:
                row.seq = event["seq"]
            if action_id in violations_by_action:
                violation = violations_by_action[action_id]
                row.roe_status = violation["roe_status"]
                row.roe_dimension = violation["roe_dimension"]
                row.roe_categories = violation["roe_categories"]
                row.roe_category = row.roe_categories[0] if row.roe_categories else None
            elif result.get("roe") and action_id in unclassified_by_action:
                row.roe_status = "unclassified"
            elif result.get("roe"):
                row.roe_status = "allowed"
            elif action_id in live_roe_by_action:
                verdict = live_roe_by_action[action_id]
                row.roe_status = verdict.get("status")
                row.roe_categories = list(verdict.get("categories") or [])
                row.roe_category = row.roe_categories[0] if row.roe_categories else None
        goal = result.get("goal") or {}
        goal_evidence = goal.get("evidence") or []
        goal_seqs = {item.get("seq") for item in goal_evidence if item.get("seq") is not None}
        if goal.get("success") and goal_seqs:
            for row in actions.values():
                if row.seq in goal_seqs and row.roe_status != "escaped":
                    row.roe_status = "goal"
        return sorted(actions.values(), key=lambda row: row.seq)

    def load_overlay(self, run_dir: Path) -> Overlay:
        paths = _manifest_paths(run_dir)
        result = _read(_art(paths, "result", "result.json") or run_dir / "result.json", {}) or {}
        progress = result.get("progress", {}) or {}
        roe = result.get("roe", {}) or {}
        return Overlay(phases=progress.get("completed_stages", []),
                       goal_marker={"seq": result.get("goal", {}).get("achieved_step"), "achieved_step": result.get("goal", {}).get("achieved_step")} if result.get("goal", {}).get("success") else None,
                       roe_violations=[{"category": key, **value} for key, value in roe.get("categories", {}).items() if value.get("status") == "violation"])

    def load_capability_overlay(self, run_dir: Path) -> CapabilityOverlay:
        paths = _manifest_paths(run_dir)
        result = _read(_art(paths, "result", "result.json") or run_dir / "result.json", {}) or {}
        progress = result.get("progress", {}) or {}
        goal = result.get("goal", {}) or {}
        roe = result.get("roe", {}) or {}

        evidence_by_stage = progress.get("evidence", {}) or {}
        capability_stages = []
        for stage in progress.get("completed_stages", []) or []:
            seqs = [item.get("seq") for item in evidence_by_stage.get(stage, []) or [] if item.get("seq") is not None]
            capability_stages.append(CapabilityStage(name=stage, start_seq=min(seqs) if seqs else None, end_seq=max(seqs) if seqs else None))

        goal_marker = None
        if goal.get("success"):
            goal_evidence = goal.get("evidence") or []
            goal_marker = {"seq": goal_evidence[0].get("seq") if goal_evidence else None, "achieved_step": goal.get("achieved_step")}

        roe_violations = [
            {
                "seq": violation.get("seq"),
                "step": violation.get("step"),
                "dimension": violation.get("dimension"),
                "roe_categories": violation.get("roe_categories"),
                "reason": violation.get("reason"),
                "severity": violation.get("severity"),
            }
            for violation in roe.get("violations", []) or []
        ]

        return CapabilityOverlay(capability_stages=capability_stages, goal_marker=goal_marker, roe_violations=roe_violations)