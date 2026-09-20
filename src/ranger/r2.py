from collections.abc import Mapping, Sequence
from typing import Any


def interpret_r2_action(normalized_action: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    if normalized_action.get("action_channel") == "native_http":
        return {
            "policy_violation": False,
            "classification_status": "not_applicable",
            "tool_authorization": "not_applicable",
            "tool_usage_intent": "not_applicable",
            "tool_rule": None, "intent_rule": None, "matched_rules": [],
            "matched_rule": None, "tool": {"name": None, "family": None},
            "intent": normalized_action.get("intent"),
        }
    tool = normalized_action.get("tool")
    tool = tool if isinstance(tool, Mapping) else {}
    name = tool.get("name")
    family = tool.get("family")
    intent = normalized_action.get("intent")
    normalization_status = normalized_action.get("normalization_status", "normalized")
    allowed_tools = tuple(policy.get("allowed_tools", policy.get("authorized_tools", ())))
    prohibited_tools = tuple(policy.get("prohibited_tools", policy.get("excluded", ())))
    allowed_intents = tuple(policy.get("allowed_intents", ()))
    prohibited_intents = tuple(policy.get("prohibited_intents", ()))
    tool_enabled = bool(allowed_tools or prohibited_tools)
    intent_enabled = bool(allowed_intents or prohibited_intents)

    tool_status, tool_rule = _tool_decision(
        name, family, normalization_status, allowed_tools, prohibited_tools, tool_enabled,
    )
    intent_status, intent_rule = _value_decision(
        intent, allowed_intents, prohibited_intents, intent_enabled, "intents",
    )
    violation = tool_status == "violation" or intent_status == "violation"
    unclassified = tool_status == "unclassified" or intent_status == "unclassified"
    return {
        "policy_violation": violation,
        "classification_status": "unclassified" if unclassified else "classified",
        "tool_authorization": tool_status,
        "tool_usage_intent": intent_status,
        "tool_rule": tool_rule,
        "intent_rule": intent_rule,
        "matched_rules": [rule for rule in (tool_rule, intent_rule) if rule],
        "matched_rule": tool_rule if tool_status == "violation" else intent_rule if intent_status == "violation" else tool_rule or intent_rule,
        "tool": {"name": name, "family": family},
        "intent": intent,
    }


def _tool_decision(name: Any, family: Any, normalization_status: Any,
                   allowed: Sequence[Any], prohibited: Sequence[Any], enabled: bool) -> tuple[str, str | None]:
    if not enabled:
        return "pass", None
    for rule in prohibited:
        if tool_rule_matches(name, family, rule):
            return "violation", f"prohibited_tools.{rule_label(rule)}"
    if normalization_status == "unclassified" or name in (None, "unknown"):
        return "unclassified", None
    if allowed and not any(tool_rule_matches(name, family, rule) for rule in allowed):
        return "violation", "allowed_tools"
    return "pass", f"allowed_tools.{name}" if allowed else None


def tool_decision(name: Any, family: Any, normalization_status: Any,
                  allowed: Sequence[Any], prohibited: Sequence[Any], *,
                  enabled: bool) -> tuple[str, str | None]:
    return _tool_decision(name, family, normalization_status, allowed, prohibited, enabled)


def _value_decision(value: Any, allowed: Sequence[Any], prohibited: Sequence[Any],
                    enabled: bool, prefix: str) -> tuple[str, str | None]:
    if not enabled:
        return "pass", None
    for rule in prohibited:
        if value == rule:
            return "violation", f"prohibited_{prefix}.{value}"
    if value is None:
        return "unclassified", None
    if allowed and value not in allowed:
        return "violation", f"allowed_{prefix}"
    return "pass", f"allowed_{prefix}.{value}" if allowed else None


def value_decision(value: Any, allowed: Sequence[Any], prohibited: Sequence[Any], *,
                   enabled: bool, prefix: str) -> tuple[str, str | None]:
    return _value_decision(value, allowed, prohibited, enabled, prefix)


def tool_rule_matches(name: Any, family: Any, rule: Any) -> bool:
    if isinstance(rule, Mapping):
        return (("name" in rule and name == rule["name"])
                or ("family" in rule and family == rule["family"]))
    if not isinstance(rule, str):
        return False
    return family == rule[7:] if rule.startswith("family:") else name == rule


def rule_label(rule: Any) -> str:
    if isinstance(rule, Mapping):
        return str(rule.get("name", rule.get("family", "unknown")))
    return str(rule).replace("family:", "")