"""Generic trusted HTTP report acceptance observation."""

import json
from collections.abc import Mapping
from typing import Any


def observe_report_acceptance(facts: Mapping[str, Any], contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return redacted acceptance facts correlated to the gateway event."""
    body = _json_object(facts.get("_request_body"))
    response = _json_object(facts.get("_response_body"))
    contract_path = contract.get("path", contract.get("route"))
    path_ok = facts.get("path") == contract_path
    method_ok = str(facts.get("method", "")).upper() == str(contract.get("method", "POST")).upper()
    fields = tuple(str(item) for item in contract.get("required_fields", ()))
    fields_ok = bool(body) and all(field in body and body[field] not in (None, "") for field in fields)
    expected = contract.get("expected_fields", {})
    expected_ok = isinstance(expected, Mapping) and all(body.get(key) == value for key, value in expected.items())
    response_fields = tuple(str(item) for item in contract.get("response_fields", ()))
    response_ok = bool(response) and all(field in response for field in response_fields)
    accepted = bool(
        path_ok and method_ok and facts.get("target_executed") is True and fields_ok and expected_ok and response_ok
        and isinstance(facts.get("status"), int) and 200 <= facts["status"] < 300
    )
    semantic_attributes, semantic_status = _semantic_attributes(
        body, contract.get("semantic_fields", {}), accepted,
    )
    outcome_name = contract.get("outcome_name")
    return {
        "action_id": facts.get("action_id"), "seq": facts.get("seq"),
        "evidence_type": "report_acceptance", "source": "gateway_report_observer",
        "trust_level": "trusted" if accepted else "unclassified",
        "designated_endpoint": path_ok and method_ok,
        "target_executed": facts.get("target_executed") is True,
        "report_contract_satisfied": fields_ok and expected_ok,
        "response_acceptance": response_ok and accepted,
        "report_accepted": accepted,
        "trusted_report_evidence": accepted,
        "realized_outcome": outcome_name if accepted and isinstance(outcome_name, str) else None,
        "status": "confirmed" if accepted else "unclassified",
        "contract_fields_present": sorted(field for field in fields if field in body),
        "response_fields_present": sorted(field for field in response_fields if field in response),
        "semantic_attributes": semantic_attributes if accepted else {},
        "semantic_status": semantic_status if accepted else "unclassified",
    }


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}
    return {}


def _semantic_attributes(
    body: Mapping[str, Any], mapping: Any, accepted: bool,
) -> tuple[dict[str, Any], str]:
    if not isinstance(mapping, Mapping) or not mapping:
        return {}, "unclassified"
    attributes: dict[str, Any] = {}
    status = "confirmed"
    for destination, specification in mapping.items():
        source = specification
        if isinstance(specification, Mapping):
            if "value" in specification:
                value = specification["value"]
                source = None
            else:
                source = specification.get("source")
                value = body.get(source) if isinstance(source, str) else None
        elif source == "acceptance":
            value = accepted
            source = None
        else:
            value = body.get(source) if isinstance(source, str) else None
        if value is None:
            status = "unclassified"
        attributes[str(destination)] = _redact_semantic_value(source, value)
    return attributes, status


def _redact_semantic_value(source: Any, value: Any) -> Any:
    name = str(source or "").casefold()
    if any(token in name for token in ("token", "password", "digest", "secret")):
        return "[REDACTED]"
    return value
