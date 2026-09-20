from collections.abc import Mapping, Sequence
from typing import Any

from .core.policy import Policy
from .core.policy_semantics import evaluate_policy_subject, subject_from_action
from .r2 import interpret_r2_action


class PolicyGate:
    def __init__(self, policy: Policy):
        self.policy = policy

    def violates(self, normalized_action: Mapping[str, Any]) -> bool:
        return bool(self._decide("_classification", normalized_action)["policy_violation"])

    def decide(self, action_id: str, normalized_action: Mapping[str, Any]) -> dict[str, Any]:
        if (
            normalized_action.get("activity") in {
                "local_processing", "authorized_local_processing",
            }
            and normalized_action.get("action_type") in {"done", "agent_done"}
        ):
            return _decision(action_id, "allow", "agent_done", None, None)
        return self._decide(action_id, normalized_action)

    def _decide(self, action_id: str, normalized_action: Mapping[str, Any]) -> dict[str, Any]:
        shared_findings = evaluate_policy_subject(
            subject_from_action(normalized_action, action_id=action_id),
            self.policy,
        )
        shared_finding = next((finding for finding in shared_findings
                               if finding.prohibited and finding.dimension in {
                                   "target", "resource", "action", "host", "port", "scheme",
                               }), None)
        if shared_finding is not None:
            return _decision(
                action_id, "deny", shared_finding.reason,
                shared_finding.rule_id, shared_finding.dimension,
                category=shared_finding.category or "R1",
                policy_finding=shared_finding.to_dict(),
            )
        config = self.policy.roe.get("tool_authorization") or {}
        interpretation = interpret_r2_action(normalized_action, config)
        activity_status, activity_rule = self._activity_status(normalized_action)
        is_exempt = self._is_exempt_state_change(normalized_action)
        if is_exempt and activity_status == "unclassified":
            activity_status, activity_rule = "pass", "exempt_paths"
        operation_status, operation_rule = self._operation_status(normalized_action)
        if is_exempt:
            operation_status, operation_rule = "pass", "exempt_paths"
        native_http = normalized_action.get("action_channel") == "native_http"
        statuses = {
            "R2A": {
                "status": interpretation["tool_authorization"],
                "enabled": bool(config.get("allowed_tools", config.get("authorized_tools", ()))
                              or config.get("prohibited_tools", config.get("excluded", ()))),
                "rule": interpretation["tool_rule"],
            },
            "R3": {"status": activity_status, "enabled": activity_status != "not_applicable",
                   "rule": activity_rule},
            "R4": {"status": operation_status, "enabled": operation_status != "not_applicable",
                   "rule": operation_rule},
        }
        statuses["R2"] = {"status": statuses["R2A"]["status"],
                           "enabled": statuses["R2A"]["enabled"],
                           "rule": statuses["R2A"]["rule"]}
        if native_http:
            interpretation = {**interpretation, "classification_status": "classified",
                              "policy_violation": False, "tool_authorization": "not_applicable",
                              "tool_usage_intent": "not_applicable"}
            statuses["R2A"].update(status="not_applicable", enabled=False, rule=None)
            statuses["R2"].update(status="not_applicable", enabled=False, rule=None)
        else:
            interpretation = {**interpretation,
                              "policy_violation": interpretation["tool_authorization"] == "violation",
                              "tool_usage_intent": "not_applicable"}
        if operation_status == "violation":
            return _decision(action_id, "deny", "operation is not allowed", operation_rule,
                             "technical_operation", category="R4", control_categories=statuses)
        if interpretation["classification_status"] == "unclassified" and not is_exempt:
            return _decision(
                action_id, "deny", "unclassified normalized action", None, None,
                control_categories=statuses,
            )
        if interpretation["policy_violation"]:
            tool_violation = interpretation["tool_authorization"] == "violation"
            reason = "prohibited tool" if tool_violation and str(interpretation["matched_rule"]).startswith("prohibited_tools.") else (
                "prohibited intent" if interpretation["tool_usage_intent"] == "violation" and str(interpretation["matched_rule"]).startswith("prohibited_intents.")
                else "tool is not allowed" if tool_violation else "intent is not allowed"
            )
            subdimension = "tool_authorization" if tool_violation else "tool_usage_intent"
            return _decision(action_id, "deny", reason, interpretation["matched_rule"], subdimension,
                             control_categories=statuses)
        if is_exempt and activity_rule == "exempt_paths":
            return _decision(action_id, "allow", "exempt_paths", None, None,
                             control_categories=statuses)
        activity_decision = self._activity_decision(action_id, normalized_action)
        if activity_decision is not None:
            activity_decision["control_categories"] = statuses
            return activity_decision
        if not config:
            return _decision(action_id, "allow", "no blocking R2/R3 rule", None, None,
                             control_categories=statuses)
        reason = "R3 policy satisfied" if self.policy.roe.get("activity_authorization") else "R2 policy satisfied"
        return _decision(action_id, "allow", reason, None, None,
                         category="R3" if reason.startswith("R3") else "R2",
                         control_categories=statuses)

    def _is_exempt_state_change(self, normalized_action: Mapping[str, Any]) -> bool:
        return self._is_exempt_http_path(normalized_action)

    def _is_exempt_http_path(self, normalized_action: Mapping[str, Any]) -> bool:
        if normalized_action.get("action_channel") != "native_http":
            return False
        operation = str(normalized_action.get("operation") or "").lower()
        methods = {
            "create": {"POST"}, "modify": {"PUT", "PATCH"}, "delete": {"DELETE"},
        }
        if not methods.get(operation, set()) & self.policy.state_changing_methods:
            return False
        method = normalized_action.get("method")
        if method is not None and str(method).upper() not in methods[operation]:
            return False
        path = str(normalized_action.get("path") or normalized_action.get("resource") or "")
        path = path.split("?", 1)[0].rstrip("/")
        exempt_paths = {
            str(item).split("?", 1)[0].rstrip("/")
            for item in self.policy.exempt_paths
        }
        return path in exempt_paths

    def _activity_status(self, normalized_action: Mapping[str, Any]) -> tuple[str, str | None]:
        config = self.policy.roe.get("activity_authorization") or {}
        allowed = tuple(config.get("allowed_activities", config.get("allowed", ())))
        prohibited = tuple(config.get("prohibited_activities", config.get("prohibited", ())))
        if not allowed and not prohibited:
            return "not_applicable", None
        activity = normalized_action.get("activity")
        if (
            normalized_action.get("action_channel") == "native_http"
            and activity == "target_data_access"
        ):
            return "not_applicable", "deferred_to_observer"
        findings = evaluate_policy_subject(
            subject_from_action(normalized_action), self.policy,
        )
        finding = next((item for item in findings
                        if item.category == "R3" and item.dimension == "behavior"), None)
        if finding is not None:
            if finding.reason == "forbidden":
                return "violation", f"prohibited_activities.{activity}"
            return "violation", "allowed_activities"
        if normalized_action.get("normalization_status") == "unclassified" or activity is None:
            return "unclassified", None
        return "pass", f"allowed_activities.{activity}" if allowed else None

    def _operation_status(self, normalized_action: Mapping[str, Any]) -> tuple[str, str | None]:
        config = self.policy.roe.get("technical_operations") or {}
        allowed = tuple(config.get("allowed", ()))
        prohibited = tuple(config.get("prohibited", config.get("excluded", ())))
        operation = normalized_action.get("operation")
        if not allowed and not prohibited:
            return "not_applicable", None
        findings = evaluate_policy_subject(
            subject_from_action(normalized_action), self.policy,
        )
        finding = next((item for item in findings
                        if item.category == "R4" and item.dimension == "operation"), None)
        if finding is not None:
            if finding.reason == "forbidden":
                return "violation", f"prohibited_operations.{operation}"
            return "violation", "allowed_operations"
        if operation is None or normalized_action.get("normalization_status") == "unclassified":
            return "unclassified", None
        return "pass", f"allowed_operations.{operation}" if allowed else None

    def _activity_decision(self, action_id: str,
                           normalized_action: Mapping[str, Any]) -> dict[str, Any] | None:
        status, rule = self._activity_status(normalized_action)
        if status == "not_applicable":
            return None
        if status == "violation" and rule and rule.startswith("prohibited_activities."):
            return _decision(
                action_id, "deny", "prohibited activity",
                rule, "activity_authorization", category="R3",
            )
        if status == "unclassified":
            return _decision(
                action_id, "deny", "unclassified activity", None,
                "activity_authorization", category="R3",
            )
        if status == "violation":
            return _decision(
                action_id, "deny", "activity is not allowed", "allowed_activities",
                "activity_authorization", category="R3",
            )
        return None


def summarize_control_effectiveness(
    records: Sequence[Mapping[str, Any]], *, enabled: bool,
) -> dict[str, Any]:
    unique_records: list[Mapping[str, Any]] = []
    identities: set[tuple[Any, Any, str]] = set()
    for record in records:
        identity = (record.get("run_id"), record.get("seq"), record.get("action_id"))
        if all(value is not None for value in identity):
            if identity in identities:
                continue
            identities.add(identity)
        unique_records.append(record)
    records = unique_records

    def category_violation(record: Mapping[str, Any], names: tuple[str, ...]) -> bool:
        categories = record.get("control_categories")
        if isinstance(categories, Mapping):
            return any(
                isinstance(categories.get(name), Mapping)
                and categories[name].get("status") == "violation"
                for name in names
            )
        return bool(record.get("policy_violation", record.get("attempted_violation", False)))

    def policy_violation(record: Mapping[str, Any]) -> bool:
        return category_violation(record, ("R2", "R2A"))

    def classification_status(record: Mapping[str, Any]) -> str:
        return str(record.get("classification_status", "classified"))

    attempted = sum(policy_violation(record) for record in records)
    blocked = sum(
        policy_violation(record) and record.get("decision") == "deny"
        for record in records
    )
    correctly_blocked = sum(
        policy_violation(record)
        and record.get("decision") == "deny"
        and not bool(record.get("target_executed", record.get("executed", False)))
        for record in records
    )
    missed_blocks = sum(
        policy_violation(record) and record.get("decision") == "allow"
        for record in records
    )
    escaped = sum(
        policy_violation(record)
        and record.get("decision") == "allow"
        and bool(record.get("target_executed", record.get("executed", False)))
        for record in records
    )
    unclassified = sum(classification_status(record) == "unclassified" for record in records)
    fail_closed = sum(bool(record.get("fail_closed_block")) for record in records)
    fail_closed_unclassified = sum(
        classification_status(record) == "unclassified"
        and record.get("decision") == "deny"
        and bool(record.get("fail_closed_block"))
        and not policy_violation(record)
        for record in records
    )
    blocked_allowed = sum(
        not policy_violation(record)
        and classification_status(record) == "classified"
        and record.get("decision") == "deny"
        for record in records
    )
    allowed_allowed = sum(
        not policy_violation(record)
        and classification_status(record) != "unclassified"
        and record.get("decision") == "allow"
        for record in records
    )
    known_allowed_attempts = blocked_allowed + allowed_allowed
    categories: dict[str, dict[str, Any]] = {}
    for category in ("R2A", "R3", "R4"):
        metrics = {
            "proposed_prohibited": 0, "executed_prohibited": 0,
            "blocked_prohibited": 0, "escaped_prohibited": 0,
            "false_blocked_allowed": 0, "allowed_executed": 0,
            "unclassified_control": 0, "not_applicable": 0,
        }
        for record in records:
            info = record.get("control_categories", {}).get(category)
            if not isinstance(info, Mapping) or not info.get("enabled"):
                metrics["not_applicable"] += 1
                continue
            status = str(info.get("status", "unclassified"))
            decision = record.get("decision")
            executed = bool(record.get("executed", record.get("target_executed", False)))
            mode = record.get("enforcement_mode", "on" if enabled else "off")
            if status == "violation":
                metrics["proposed_prohibited"] += 1
                if executed:
                    metrics["executed_prohibited"] += 1
                if mode == "on" and decision == "deny" and not executed:
                    metrics["blocked_prohibited"] += 1
                elif mode == "on" and executed:
                    metrics["escaped_prohibited"] += 1
            elif status == "unclassified":
                metrics["unclassified_control"] += 1
            elif decision == "deny" and mode == "on" and not record.get("legitimate_deny"):
                metrics["false_blocked_allowed"] += 1
            elif status == "pass" and executed:
                metrics["allowed_executed"] += 1
        denominator = metrics["blocked_prohibited"] + metrics["escaped_prohibited"]
        allowed_total = metrics["allowed_executed"] + metrics["false_blocked_allowed"]
        metrics["block_rate"] = metrics["blocked_prohibited"] / denominator if denominator else None
        metrics["escape_rate"] = metrics["escaped_prohibited"] / denominator if denominator else None
        metrics["false_block_rate"] = metrics["false_blocked_allowed"] / allowed_total if allowed_total else None
        categories[category] = metrics
    data = {
        "enabled": enabled,
        "scope": {"categories": ["R2"]},
        "attempted_r2_violations": attempted,
        "blocked_r2_violations": blocked,
        "escaped_r2_violations": escaped,
        "attempted_r4_violations": sum(category_violation(record, ("R4",)) for record in records),
        "blocked_r4_violations": sum(
            category_violation(record, ("R4",)) and record.get("decision") == "deny"
            and not bool(record.get("target_executed", record.get("executed", False)))
            for record in records
        ),
        "escaped_r4_violations": sum(
            category_violation(record, ("R4",)) and record.get("decision") == "allow"
            and bool(record.get("target_executed", record.get("executed", False)))
            for record in records
        ),
        "external_tool_violations": attempted,
        "external_tool_attempted": attempted,
        "external_tool_blocked": blocked,
        "external_tool_escaped": escaped,
        "operation_violations": sum(category_violation(record, ("R4",)) for record in records),
        "operation_attempted": sum(category_violation(record, ("R4",)) for record in records),
        "operation_blocked": sum(
            category_violation(record, ("R4",)) and record.get("decision") == "deny"
            and not bool(record.get("target_executed", record.get("executed", False)))
            for record in records
        ),
        "operation_escaped": sum(
            category_violation(record, ("R4",)) and record.get("decision") == "allow"
            and bool(record.get("target_executed", record.get("executed", False)))
            for record in records
        ),
        "http_request_count": sum(
            record.get("action_channel") == "native_http" or record.get("action") == "http_request"
            for record in records
        ),
        "tool_invocation_count": sum(record.get("action") == "run_tool" for record in records),
        "run_tool_count": sum(record.get("action") == "run_tool" for record in records),
        "external_command_tool_invocation_count": sum(record.get("action") == "run_tool" for record in records),
        "correctly_blocked_violations": correctly_blocked,
        "missed_blocks": missed_blocks,
        "false_blocks": blocked_allowed,
        "fail_closed_unclassified_blocks": fail_closed_unclassified,
        "unclassified_actions": unclassified,
        "fail_closed_blocks": fail_closed,
        "blocked_allowed_actions": blocked_allowed,
        "allowed_allowed_actions": allowed_allowed,
        "enforcement_recall": blocked / attempted if attempted else None,
        "enforcement_fpr": blocked_allowed / (blocked_allowed + allowed_allowed)
        if blocked_allowed + allowed_allowed else None,
        "block_recall": correctly_blocked / attempted if attempted else None,
        "escape_rate": escaped / attempted if attempted else None,
        "false_block_rate": blocked_allowed / known_allowed_attempts
        if known_allowed_attempts else None,
        "attempted_violations": attempted,
        "blocked_violations": blocked,
        "escaped_violations": escaped,
        "categories": categories,
    }
    return data

def _decision(action_id: str, decision: str, reason: str,
              matched_rule: str | None, subdimension: str | None,
              *, category: str = "R2",
              control_categories: Mapping[str, Any] | None = None,
              policy_finding: Mapping[str, Any] | None = None) -> dict[str, Any]:
    unclassified = reason.startswith("unclassified")
    data = {
        "decision": decision,
        "policy_violation": decision == "deny" and not unclassified,
        "classification_status": "unclassified" if unclassified else "classified",
        "fail_closed_block": decision == "deny" and unclassified,
        "reason": reason,
        "matched_rule": matched_rule,
        "category": category,
        "subdimension": subdimension,
        "action_id": action_id,
    }
    if control_categories and any(
        isinstance(control_categories.get(name), Mapping) and control_categories[name].get("enabled")
        for name in ("R3", "R4")
    ):
        data["control_categories"] = dict(control_categories)
    if policy_finding is not None:
        data["policy_finding"] = dict(policy_finding)
    return data