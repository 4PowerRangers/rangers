"""Convert raw tool calls into a small canonical action vocabulary."""

from dataclasses import asdict, dataclass
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .detectors.injection import detect_injection

Adapter = Callable[[Mapping[str, Any]], "CanonicalAction"]


@dataclass(frozen=True)
class CanonicalAction:
    tool: dict[str, Any] | None
    action_channel: str = "command"
    protocol: str | None = None
    intent: str | None = None
    attack_family: str | None = None
    activity: str | None = None
    operation: str | None = None
    target: dict[str, Any] | None = None
    resource: str | None = None
    normalization_status: str = "normalized"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_ADAPTERS: dict[str, Adapter] = {}
_SUPPORTED_OPERATIONS = {"read", "create", "modify", "delete", "execute", "invoke"}
_LOCAL_COMMANDS = {"python", "python3", "bash", "sh"}
_NON_HTTP_ACTIONS = {"done", "agent_done", "local_processing", "reasoning"}
_LOCAL_UNSAFE = re.compile(
    r"(?:https?://|\b(?:curl|wget|nc|ncat|nmap|ssh|scp|ftp)\b|"
    r"/(?:etc|proc|sys|home|root)(?:/|\b)|\b(?:cat|open|printenv|env|rm|mv|cp|chmod|dd|kill|docker)\b)",
    re.IGNORECASE,
)


def register_adapter(*identities: str) -> Callable[[Adapter], Adapter]:
    def decorator(adapter: Adapter) -> Adapter:
        for identity in identities:
            _ADAPTERS[identity.casefold()] = adapter
        return adapter
    return decorator


def _tool(raw: Mapping[str, Any]) -> dict[str, Any]:
    value = raw.get("tool")
    if isinstance(value, Mapping):
        return {
            "name": str(value.get("name", "unknown")),
            "type": str(value.get("type", "other")),
            "family": str(value.get("family", "other")),
        }
    if isinstance(value, str):
        return {"name": value, "type": "other", "family": "other"}
    return {"name": "unknown", "type": "other", "family": "other"}


def _url_parts(raw: Mapping[str, Any]) -> tuple[str | None, str | None, int | None, str | None]:
    url = raw.get("url") or raw.get("target_url")
    if not isinstance(url, str):
        target = raw.get("target")
        url = target if isinstance(target, str) else None
    if not url:
        return None, None, None, None
    parsed = urlsplit(url)
    return parsed.scheme or None, parsed.hostname, parsed.port, parsed.path or "/"


def _target(raw: Mapping[str, Any], host: str | None = None) -> dict[str, Any]:
    value = raw.get("target") if isinstance(raw.get("target"), Mapping) else {}
    return {
        "host": value.get("host", raw.get("destination_host", host)),
        "port": value.get("port", raw.get("destination_port")),
        "application": value.get("application", raw.get("application")),
    }


def _operation(raw: Mapping[str, Any]) -> str | None:
    if raw.get("operation") is not None:
        return str(raw["operation"])
    method = str(raw.get("method", "")).upper()
    return {"GET": "read", "HEAD": "read", "POST": "create", "PUT": "modify",
            "PATCH": "modify", "DELETE": "delete"}.get(method)


def _http_activity(raw: Mapping[str, Any], resource: Any,
                   operation: str | None) -> str | None:
    explicit = raw.get("activity")
    if explicit is not None:
        return str(explicit)
    if operation != "read":
        return None
    method = str(raw.get("method", "")).upper()
    path = str(resource or "/").split("?", 1)[0]
    routes = raw.get("activity_routes")
    if isinstance(routes, Mapping) and method in {"GET", "HEAD"}:
        for activity, configured in routes.items():
            if not isinstance(configured, (list, tuple)):
                continue
            for route in configured:
                if isinstance(route, str):
                    route_path, methods = route, {"GET", "HEAD"}
                elif isinstance(route, Mapping):
                    route_path = route.get("path")
                    methods = {str(item).upper() for item in route.get("methods", ("GET", "HEAD"))}
                else:
                    continue
                if path == route_path and method in methods:
                    return str(activity)
    return "target_data_access"


def _http(raw: Mapping[str, Any]) -> CanonicalAction:
    tool = _tool(raw)
    native_http = tool.get("name", "").casefold() == "http_request"
    protocol, parsed_host, parsed_port, parsed_resource = _url_parts(raw)
    resource = raw.get("path") or raw.get("resource") or parsed_resource
    operation = _operation(raw)
    target = _target(raw, parsed_host)
    if target["port"] is None:
        target["port"] = parsed_port
    status = (
        "normalized" if resource and operation in _SUPPORTED_OPERATIONS and target.get("host")
        else "unclassified"
    )
    intent = {
        "read": "resource_read", "create": "resource_create",
        "modify": "resource_modify", "delete": "resource_delete",
    }.get(operation)
    activity = _http_activity(raw, resource, operation)
    attack_family = None
    injection = detect_injection(
        method=str(raw.get("method", "")).upper(),
        path=resource,
        content_type=(raw.get("content_type") or raw.get("Content-Type")
                      or (raw.get("headers", {}).get("Content-Type")
                          if isinstance(raw.get("headers"), Mapping) else None)),
        body=raw.get("body"),
    )
    if injection["status"] == "ambiguous":
        status = "unclassified"
    elif injection["classified"]:
        intent = injection["intent"]
        activity = "exploitation"
        attack_family = injection["attack_family"]
    else:
        attack_family = None
    return CanonicalAction(
        tool=None if native_http else tool,
        action_channel="native_http" if native_http else "command",
        protocol=protocol or "http", intent=intent,
        activity=activity,
        operation=operation, target=target, resource=resource,
        normalization_status=status,
        attack_family=attack_family,
    )


@register_adapter("http_request", "curl", "browser", "python_requests")
def _http_adapter(raw: Mapping[str, Any]) -> CanonicalAction:
    return _http(raw)


def classify_local_command(argv: Any) -> dict[str, Any]:
    """Classify only explicitly local, stdout-oriented command processing."""
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        return {"intent": None, "activity": None, "operation": None,
                "normalization_status": "unclassified", "activity_classification": "unclassified"}
    executable = argv[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    command = " ".join(argv)
    if executable not in _LOCAL_COMMANDS:
        return {"intent": None, "activity": None, "operation": None,
                "normalization_status": "unclassified", "activity_classification": "unclassified"}
    if _LOCAL_UNSAFE.search(command):
        if re.search(r"(?:https?://|\b(?:curl|wget|nc|ncat|nmap|ssh|scp|ftp)\b)", command, re.IGNORECASE):
            return {"action_channel": "command", "intent": "network_access",
                    "activity": "network_access", "operation": "network_scan",
                    "normalization_status": "normalized", "activity_classification": "classified",
                    "activity_evidence_markers": ["local_argv", "network_access"]}
        return {"intent": None, "activity": None, "operation": None,
                "normalization_status": "unclassified", "activity_classification": "unclassified"}
    operation = "local_decode" if re.search(r"\bbase64\b", command, re.IGNORECASE) else "local_transform"
    return {
        "action_channel": "command",
        "intent": "local_processing",
        "activity": "authorized_local_processing",
        "operation": operation,
        "normalization_status": "normalized",
        "activity_classification": "classified",
        "activity_evidence_markers": ["local_argv", "stdout_processing"],
    }


@register_adapter("sqlmap")
def _sqlmap(raw: Mapping[str, Any]) -> CanonicalAction:
    tool = _tool(raw)
    if tool["family"] == "other":
        tool["family"] = "security_scanner"
    target = _target(raw)
    target_value = raw.get("target")
    if isinstance(target_value, str):
        target["application"] = target["application"] or target_value
    return CanonicalAction(
        tool=tool, protocol="http", intent="exploit_test",
        activity="exploitation", operation=None, target=target,
        resource=raw.get("resource"),
        normalization_status="normalized" if target["application"] else "unclassified",
    )


def normalize_action(raw: Mapping[str, Any] | Any) -> CanonicalAction:
    if not isinstance(raw, Mapping):
        return CanonicalAction(
            tool={"name": "unknown", "type": "other", "family": "other"},
            normalization_status="unclassified",
        )
    tool = _tool(raw)
    adapter = _ADAPTERS.get(tool["name"].casefold()) or _ADAPTERS.get(tool["type"].casefold())
    if adapter is None:
        action_type = raw.get("action") or raw.get("type")
        action_type = str(action_type or "").casefold()
        if action_type in {"done", "agent_done"} or (
            raw.get("method") is None and action_type in _NON_HTTP_ACTIONS
        ):
            allowed = raw.get("_allowed_activities")
            activity = (
                "authorized_local_processing"
                if isinstance(allowed, (list, tuple, set))
                and "authorized_local_processing" in allowed
                else "local_processing"
            )
            return CanonicalAction(
                tool=tool, intent="local_processing", activity=activity,
                operation="execute", normalization_status="normalized",
            )
        return CanonicalAction(tool=tool, normalization_status="unclassified")
    try:
        return adapter(raw)
    except (KeyError, TypeError, ValueError):
        return CanonicalAction(tool=tool, normalization_status="unclassified")