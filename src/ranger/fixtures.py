"""Per-run scenario fixture resolution: deterministic, template-based identity.

State-changing scenarios (registration, feedback, reviews, baskets, uploads,
coupons, password reset, user modification, ...) that use a fixed literal
identity (a hardcoded email, username, filename, ...) collide across
back-to-back runs against a shared target -- most visibly when a capability
and a restraint condition run against the same target within one experiment.

Scenario YAML may declare a top-level ``fixtures:`` mapping so each run gets
its own deterministic identity instead. This module resolves that mapping
ONCE per run into concrete values, then substitutes ``{fixture_name}``
placeholders anywhere they appear in the scenario/policy documents (goal
marker, success_when, agent_instructions, ...). Scenarios that declare no
``fixtures:`` block are completely unaffected -- every function here is a
no-op on an absent/empty fixtures mapping.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def infer_condition(policy_stem: str | None) -> str:
    """Best-effort restraint/capability label derived from the policy filename.

    ``policy_stem`` is the policy file's name without extension (e.g.
    ``"policy"`` or ``"policy-capability"``), matching ``RunConfig.policy``'s
    existing convention (see runner.py's ``policy=policy_path.stem``).

    Every shipped scenario in this repo follows a fixed two-file naming
    convention (verified across scenarios/JS-*/): the restraint condition's
    policy file is always literally named ``policy.yaml`` (never
    ``policy-restraint.yaml``), and the capability-pressure variant is
    always ``policy-capability.yaml``. So the bare stem ``"policy"`` means
    restraint, any stem containing ``"capability"`` means capability, and
    anything else (a scenario-specific custom policy filename) falls back
    to ``"custom"`` rather than a misleading ``"restraint"`` guess.
    """
    stem = (policy_stem or "").casefold()
    if "capability" in stem:
        return "capability"
    if stem == "policy":
        return "restraint"
    return "custom"


def short_run_id(run_id: str, *, length: int = 12) -> str:
    """Short, filename/email-local-part-safe, deterministic derivative of run_id.

    A raw ``run_id`` can be long and can (in principle) carry characters that
    are unsafe inside an email local-part or a filename fixture value.
    Hashing keeps every fixture template short and safe regardless of the
    run_id's shape while remaining fully deterministic for a given run_id
    (same run_id -> same short_run_id, always).
    """
    return hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:length]


def build_context(*, scenario_id: str, run_id: str, condition: str,
                  run_index: int | None = None) -> dict[str, str]:
    """Build the placeholder substitution context for one run.

    Includes every placeholder this module promises to support:
    ``{scenario_id}``, ``{run_id}``, ``{condition}``, ``{short_run_id}``, and
    ``{run_index}`` when a repetition index is available.
    """
    context = {
        "scenario_id": str(scenario_id),
        "run_id": str(run_id),
        "condition": str(condition),
        "short_run_id": short_run_id(str(run_id)),
    }
    if run_index is not None:
        context["run_index"] = str(run_index)
    return context


def resolve_fixtures(fixtures_doc: Mapping[str, Any] | None,
                     context: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """Resolve one run's fixture values from scenario.yaml's ``fixtures:`` block.

    Each entry is either:
      - ``{"value": <literal>, "safe_to_record": <bool>}`` -- a fixed value
        (e.g. a controlled password) that is NOT run-templated.
      - ``{"template": "<string with {placeholders}>", "safe_to_record": <bool>}``
        -- resolved by substituting run-context placeholders
        (``{scenario_id}``, ``{run_id}``, ``{condition}``, ``{short_run_id}``,
        ``{run_index}``).

    Returns ``{name: {"value": resolved_value, "safe_to_record": bool}}``.
    ``safe_to_record`` defaults to ``False`` (fail closed: an unmarked
    fixture is treated as unsafe to write into result/provenance).

    Absent, non-mapping, or malformed fixture definitions resolve to an
    empty dict -- scenarios without a ``fixtures:`` block, or with a
    fixture entry missing both ``value`` and ``template``, behave exactly
    as if fixtures did not exist.
    """
    resolved: dict[str, dict[str, Any]] = {}
    if not isinstance(fixtures_doc, Mapping):
        return resolved
    for name, spec in fixtures_doc.items():
        if not isinstance(spec, Mapping):
            continue
        if "value" in spec:
            value = spec["value"]
        elif isinstance(spec.get("template"), str):
            value = _substitute(spec["template"], context)
        else:
            continue
        resolved[str(name)] = {
            "value": value,
            "safe_to_record": bool(spec.get("safe_to_record", False)),
        }
    return resolved


def _substitute(template: str, values: Mapping[str, Any]) -> str:
    def _replace(match: "re.Match[str]") -> str:
        key = match.group(1)
        return str(values[key]) if key in values else match.group(0)
    return _PLACEHOLDER.sub(_replace, template)


def apply_fixtures(document: Any, resolved: Mapping[str, Mapping[str, Any]]) -> Any:
    """Recursively substitute ``{fixture_name}`` placeholders with resolved values.

    Works over the shapes scenario.yaml/policy.yaml documents actually take
    (nested dict/list/str; other types are returned unchanged). A document
    with no fixture placeholders, or an empty ``resolved`` mapping (the
    no-fixtures-declared case), is returned unchanged.

    A placeholder naming a fixture that was NOT resolved (typo, or a
    fixture definition that failed to resolve) is left literally in place
    rather than raising -- this fails closed for goal matching (a dangling
    ``{name}`` string will simply never match real target output) instead
    of crashing the run.
    """
    if not resolved:
        return document
    substitutions = {name: item["value"] for name, item in resolved.items()}
    return _apply(document, substitutions)


def _apply(value: Any, substitutions: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        return _substitute(value, substitutions) if "{" in value else value
    if isinstance(value, Mapping):
        return {key: _apply(item, substitutions) for key, item in value.items()}
    if isinstance(value, list):
        return [_apply(item, substitutions) for item in value]
    if isinstance(value, tuple):
        return tuple(_apply(item, substitutions) for item in value)
    return value


def safe_fixture_summary(resolved: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Return only the fixtures explicitly marked ``safe_to_record: true``.

    Intended for embedding into ``result.json``'s provenance for
    reproducibility (e.g. the resolved account email), while values such as
    a controlled password stay out of any persisted artifact by default
    (``safe_to_record`` defaults to False in :func:`resolve_fixtures`).
    """
    return {
        name: item["value"] for name, item in resolved.items()
        if item.get("safe_to_record")
    }