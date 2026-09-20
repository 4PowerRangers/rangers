"""Build and validate self-describing run evidence bundles."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .lifecycle import validate_lifecycle
from .run import _atomic_json


SCHEMA_VERSION = "1"
_JSONL = {"jsonl", "events", "trace", "lifecycle"}
_ARTIFACTS = {
    "config": ("config.json", "json", True),
    "trace": ("trace.jsonl", "jsonl", False),
    "events": ("events.jsonl", "jsonl", True),
    "lifecycle": ("lifecycle.jsonl", "jsonl", True),
    "result": ("result.json", "json", True),
    "provenance": ("provenance.json", "json", False),
    "enforcement": ("evidence/enforcement.jsonl", "jsonl", True),
    "outcomes": ("evidence/outcomes.jsonl", "jsonl", True),
    "environment": ("evidence/environment.json", "json", True),
    "setup": ("evidence/setup.json", "json", True),
    "progress": ("progress.jsonl", "jsonl", False),
    "status": ("status.json", "json", False),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path.name}:{line_number}: record must be an object")
        records.append(value)
    return records


def _write_jsonl(path: Path, records: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(dict(record), ensure_ascii=False, default=str) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _run_id(run_dir: Path, config: Mapping[str, Any] | None, result: Mapping[str, Any] | None) -> str:
    value = (config or {}).get("run_id") or (result or {}).get("run_id") or run_dir.name
    return str(value)


def _derive_enforcement(run_id: str, lifecycle: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "action_id": record.get("action_id"),
        "seq": record.get("seq"),
        "decision": record.get("decision"),
        "policy_violation": record.get("decision") == "deny",
        "classification_status": record.get("classification_status", "classified"),
        "fail_closed_block": bool(record.get("fail_closed_block", False)),
        "category": record.get("category", "R2"),
        "subdimension": record.get("subdimension"),
        "matched_rule": record.get("matched_rule", record.get("reason")),
        "source": "lifecycle.jsonl",
    } for record in lifecycle if record.get("stage") == "policy_decision"]


def _derive_outcomes(run_id: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for event in events:
        attributes = event.get("attributes", {})
        evidence = attributes.get("outcome_evidence") if isinstance(attributes, Mapping) else None
        if isinstance(evidence, Mapping):
            evidence = [evidence]
        if not isinstance(evidence, list):
            continue
        for index, item in enumerate(evidence):
            if not isinstance(item, Mapping):
                continue
            records.append({
                "schema_version": SCHEMA_VERSION,
                "evidence_id": f"outcome-{event.get('seq', event.get('event_index', 0))}-{index}",
                "run_id": run_id,
                "action_id": item.get("action_id", attributes.get("action_id")),
                "seq": event.get("seq"),
                **dict(item),
                "source_of_truth": "events.jsonl",
            })
    return records


def _derive_environment(config: Mapping[str, Any], result: Mapping[str, Any], lifecycle: list[dict[str, Any]]) -> dict[str, Any]:
    reset = config.get("environment_reset")
    provenance = result.get("provenance") or {}
    attempted = reset is not None or any(
        item.get("type") == "target_reset_started" for item in lifecycle
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "reset": {
            "attempted": attempted,
            "verified": bool((reset or {}).get("baseline_verified")) if isinstance(reset, Mapping) else False,
            "checks": ((reset or {}).get("baseline") or {}).get("checks", {})
            if isinstance(reset, Mapping) else {},
        },
        "provision": (reset or {}).get("provision", {}) if isinstance(reset, Mapping) else {
            "attempted": False, "verified": False,
        },
        "session_isolation": (reset or {}).get("session_isolation", {}) if isinstance(reset, Mapping) else {},
        "environment_sha256": provenance.get("environment_sha256", "unknown"),
        "target_image_digest": provenance.get("target_image_digest"),
        "source_of_truth": "config.json + result.json",
    }


def _derive_setup(run_id: str, progress: list[dict[str, Any]]) -> dict[str, Any]:
    started = next((item for item in progress if item.get("type") == "scenario_provision_started"), None)
    completed = next((item for item in progress if item.get("type") == "scenario_provision_completed"), None)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "provision": {
            "attempted": started is not None,
            "verified": completed is not None,
            "fixture": (completed or started or {}).get("detail", {}).get("fixture"),
        },
        "source_of_truth": "progress.jsonl",
    }


def _write_derived(run_dir: Path, run_id: str, config: Mapping[str, Any], result: Mapping[str, Any],
                   events: list[dict[str, Any]], lifecycle: list[dict[str, Any]],
                   progress: list[dict[str, Any]]) -> None:
    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    _write_jsonl(evidence_dir / "enforcement.jsonl", _derive_enforcement(run_id, lifecycle))
    _write_jsonl(evidence_dir / "outcomes.jsonl", _derive_outcomes(run_id, events))
    _atomic_json(evidence_dir / "environment.json", _derive_environment(config, result, lifecycle))
    _atomic_json(evidence_dir / "setup.json", _derive_setup(run_id, progress))
    if result.get("provenance") is not None:
        _atomic_json(run_dir / "provenance.json", {
            "schema_version": SCHEMA_VERSION,
            **result["provenance"],
            "agent": result.get("agent_metadata", {}),
            "source_of_truth": "result.json",
        })


def _entry(run_dir: Path, path: str, artifact_type: str, required: bool) -> dict[str, Any]:
    file_path = run_dir / path
    entry = {
        "path": path.replace("\\", "/"),
        "sha256": _sha256(file_path),
        "size_bytes": file_path.stat().st_size,
        "artifact_type": artifact_type,
        "required": required,
        "schema_version": SCHEMA_VERSION,
    }
    if artifact_type == "jsonl":
        entry["record_count"] = len(_read_jsonl(file_path))
    return entry


def build_manifest(run_dir: Path, *, write: bool = True) -> dict[str, Any]:
    """Build a manifest from existing artifacts without rewriting them."""
    run_dir = Path(run_dir)
    config = _read_json(run_dir / "config.json") if (run_dir / "config.json").is_file() else {}
    result = _read_json(run_dir / "result.json") if (run_dir / "result.json").is_file() else {}
    lifecycle = _read_jsonl(run_dir / "lifecycle.jsonl") if (run_dir / "lifecycle.jsonl").is_file() else []
    events = _read_jsonl(run_dir / "events.jsonl") if (run_dir / "events.jsonl").is_file() else []
    progress = _read_jsonl(run_dir / "progress.jsonl") if (run_dir / "progress.jsonl").is_file() else []
    run_id = _run_id(run_dir, config, result)
    if write:
        _write_derived(run_dir, run_id, config, result, events, lifecycle, progress)
    warnings = []
    artifacts = {}
    for name, (path, artifact_type, required) in _ARTIFACTS.items():
        file_path = run_dir / path
        if not file_path.is_file():
            if required:
                warnings.append(f"missing artifact: {path}")
            continue
        artifacts[name] = _entry(run_dir, path, artifact_type, required)
    if "provenance" not in artifacts:
        warnings.append("legacy_incomplete: provenance.json unavailable")
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "scenario_id": config.get("scenario", result.get("scenario_id")),
        "created_at": config.get("started_at", datetime.now(timezone.utc).isoformat()),
        "agent": result.get("agent_metadata", {}),
        "status": "legacy_incomplete" if warnings else "complete",
        "artifacts": artifacts,
        "source_of_truth": {
            "lifecycle": "lifecycle.jsonl",
            "enforcement_decision": "lifecycle.jsonl",
            "normalized_action": "lifecycle.jsonl",
            "trusted_outcome": "events.jsonl",
            "final_verdict": "result.json",
            "provenance": "provenance.json" if "provenance" in artifacts else "result.json",
        },
        "warnings": warnings,
    }


def finalize_bundle(run_dir: Path) -> dict[str, Any]:
    manifest = build_manifest(run_dir, write=True)
    _atomic_json(Path(run_dir) / "manifest.json", manifest)
    return manifest


def _validate_artifacts(run_dir: Path, manifest: Mapping[str, Any], errors: list[str], warnings: list[str]) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {}
    manifest_artifacts = manifest.get("artifacts", {})
    for name, (_, _, required) in _ARTIFACTS.items():
        if required and name not in manifest_artifacts:
            errors.append(f"artifact {name}: missing manifest entry")
    for name, entry in manifest_artifacts.items():
        if not isinstance(entry, Mapping):
            errors.append(f"artifact {name}: malformed manifest entry")
            continue
        path = entry.get("path")
        if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
            errors.append(f"artifact {name}: invalid relative path")
            continue
        file_path = run_dir / path
        if not file_path.is_file():
            (errors if entry.get("required") else warnings).append(f"artifact {name}: missing")
            continue
        if _sha256(file_path) != entry.get("sha256"):
            errors.append(f"artifact {name}: sha256 mismatch")
        if file_path.stat().st_size != entry.get("size_bytes"):
            errors.append(f"artifact {name}: size mismatch")
        try:
            records[name] = _read_jsonl(file_path) if entry.get("artifact_type") in _JSONL else []
            if entry.get("artifact_type") not in _JSONL:
                _read_json(file_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"artifact {name}: parse failure: {exc}")
    return records


def validate_run(run_dir: Path) -> dict[str, Any]:
    """Validate a manifest and all required evidence correlations fail-closed."""
    run_dir = Path(run_dir)
    errors: list[str] = []
    warnings: list[str] = []
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        return {"valid": False, "errors": ["manifest missing"], "warnings": []}
    try:
        manifest = _read_json(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"valid": False, "errors": [f"manifest parse failure: {exc}"], "warnings": []}
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"unsupported manifest schema: {manifest.get('schema_version')!r}")
    records = _validate_artifacts(run_dir, manifest, errors, warnings)
    run_id = str(manifest.get("run_id", ""))
    config_path = run_dir / "config.json"
    result_path = run_dir / "result.json"
    try:
        config = _read_json(config_path) if config_path.is_file() else {}
        result = _read_json(result_path) if result_path.is_file() else {}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"core artifact parse failure: {exc}")
        config, result = {}, {}
    if config.get("run_id") not in (None, run_id):
        errors.append("config run_id mismatch")
    if result.get("run_id") not in (None, run_id):
        errors.append("result run_id mismatch")
    lifecycle = records.get("lifecycle", [])
    events = records.get("events", [])
    observed_event_actions = {
        (str(item.get("action_id")), item.get("reference", {}).get("event_seq"))
        for item in lifecycle
        if item.get("stage") == "observed" and isinstance(item.get("reference"), Mapping)
        and item["reference"].get("event_seq") is not None
    }
    if lifecycle:
        try:
            validate_lifecycle(lifecycle, expected_run_id=run_id)
        except ValueError as exc:
            errors.append(f"lifecycle invalid: {exc}")
    actions = {(str(item.get("action_id")), item.get("seq")) for item in lifecycle}
    for event in events:
        attrs = event.get("attributes", {})
        action_id = attrs.get("action_id") if isinstance(attrs, Mapping) else None
        if action_id is not None and (str(action_id), event.get("seq")) not in actions \
                and (str(action_id), event.get("seq")) not in observed_event_actions:
            errors.append(f"orphan event action: {action_id}/{event.get('seq')}")
    for violation in result.get("roe", {}).get("violations", []):
        key = violation.get("event_key")
        if isinstance(key, list) and len(key) >= 3 \
                and (str(key[2]), key[1]) not in actions \
                and (str(key[2]), key[1]) not in observed_event_actions:
            errors.append(f"orphan violation evidence: {key[2]}/{key[1]}")
    _validate_terminal_semantics(lifecycle, events, result, errors)
    enforcement = records.get("enforcement", [])
    if len(enforcement) != sum(item.get("stage") == "policy_decision" for item in lifecycle):
        errors.append("enforcement/lifecycle correlation mismatch")
    r5 = result.get("roe", {}).get("categories", {}).get("R5", {})
    if r5.get("status") == "violation" and not records.get("outcomes"):
        errors.append("R5 violation has no outcome evidence")
    if manifest.get("status") == "legacy_incomplete":
        warnings.extend(manifest.get("warnings", []))
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def _validate_terminal_semantics(lifecycle: list[dict[str, Any]],
                                 events: list[dict[str, Any]],
                                 result: Mapping[str, Any], errors: list[str]) -> None:
    """Require observations only for lifecycle paths that execute a target."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in lifecycle:
        grouped.setdefault(str(record.get("action_id")), []).append(record)
    denied = 0
    observed_event_actions = {
        (str(item.get("action_id")), item.get("reference", {}).get("event_seq"))
        for item in lifecycle
        if item.get("stage") == "observed" and isinstance(item.get("reference"), Mapping)
        and item["reference"].get("event_seq") is not None
    }
    observed_keys = {
        (str(event.get("attributes", {}).get("action_id")), event.get("seq"))
        for event in events if isinstance(event.get("attributes"), Mapping)
    }
    observed_keys.update(observed_event_actions)
    for action_id, records in grouped.items():
        decision = next((item for item in records if item.get("stage") == "policy_decision"), None)
        proposed = next((item for item in records if item.get("stage") == "proposed"), None)
        stages = {item.get("stage") for item in records}
        seq = next((item.get("seq") for item in records if item.get("seq") is not None), None)
        has_observed = "observed" in stages or (action_id, seq) in observed_keys
        if decision is None:
            if result.get("termination", {}).get("reason") == "policy_denied":
                errors.append(f"policy_denied action {action_id}: policy decision missing")
            continue
        if decision.get("decision") == "deny":
            denied += 1
            if proposed is None or not isinstance(proposed.get("normalized_action"), Mapping):
                errors.append(f"policy_denied action {action_id}: normalized proposal missing")
            if stages & {"executed", "observed"} or has_observed:
                errors.append(f"policy_denied action {action_id}: target execution evidence present")
        elif decision.get("decision") == "allow" and "executed" in stages and not has_observed:
            errors.append(f"allowed action {action_id}: observed evidence missing")
    if result.get("termination", {}).get("reason") == "policy_denied" and not denied:
        errors.append("policy_denied terminal has no deny decision")
    control = result.get("control_effectiveness", {})
    if denied and control.get("escaped_r2_violations", 0):
        errors.append("policy_denied terminal has escaped R2 violation")


def reconstruct_action_chain(run_dir: Path, action_id: str, seq: int) -> dict[str, Any]:
    """Reconstruct one proposed-to-verdict chain from authoritative artifacts."""
    run_dir = Path(run_dir)
    lifecycle = _read_jsonl(run_dir / "lifecycle.jsonl")
    events = _read_jsonl(run_dir / "events.jsonl")
    outcomes = _read_jsonl(run_dir / "evidence" / "outcomes.jsonl")
    result = _read_json(run_dir / "result.json")
    stages = {
        item.get("stage"): item for item in lifecycle
        if item.get("action_id") == action_id and item.get("seq") == seq
    }
    observed = [item for item in events if item.get("seq") == seq and
                item.get("attributes", {}).get("action_id") == action_id]
    verdict = [item for item in result.get("roe", {}).get("violations", [])
               if item.get("event_key") in ([result.get("run_id"), seq, action_id],
                                             (result.get("run_id"), seq, action_id))]
    chain = {
        "proposed": stages.get("proposed"),
        "normalized": (stages.get("proposed") or {}).get("normalized_action"),
        "policy_decision": stages.get("policy_decision"),
        "executed": stages.get("executed"),
        "observed": observed or stages.get("observed"),
        "outcomes": [item for item in outcomes if item.get("action_id") == action_id and item.get("seq") == seq],
        "verdict": verdict,
    }
    chain["complete"] = all(chain[key] for key in ("proposed", "normalized", "policy_decision", "executed", "observed", "outcomes"))
    return chain