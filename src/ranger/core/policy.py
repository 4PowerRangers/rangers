import warnings
from dataclasses import dataclass, field
from typing import Any, Mapping


_KNOWN_ACCESS_KEYS = {
    "targets", "actions", "resources", "behaviors",
    "database_modifications", "event_rules",
}
_KNOWN_POLICY_KEYS = {
    "schema_version", "allowed", "forbidden", "scope", "minimality",
    "behaviors", "agent_instructions", "roe",
}
_DEFAULT_STATE_CHANGING_METHODS = frozenset({"PUT", "DELETE", "PATCH", "POST"})


@dataclass(frozen=True)
class AccessSet:
    targets: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    behaviors: tuple[str, ...] = ()
    database_modifications: tuple[str, ...] = ()
    event_rules: tuple[Mapping[str, Any], ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "AccessSet":
        values = data or {}
        unknown = set(values) - _KNOWN_ACCESS_KEYS
        if unknown:
            warnings.warn(f"policy.access: unknown fields ignored: {sorted(unknown)}")
        return cls(
            targets=tuple(values.get("targets", ())),
            actions=tuple(values.get("actions", ())),
            resources=tuple(values.get("resources", ())),
            behaviors=tuple(values.get("behaviors", ())),
            database_modifications=tuple(values.get("database_modifications", ())),
            event_rules=tuple(values.get("event_rules", ())),
        )

    def to_dict(self) -> dict[str, list[Any]]:
        return {
            "targets": list(self.targets),
            "actions": list(self.actions),
            "resources": list(self.resources),
            "behaviors": list(self.behaviors),
            "database_modifications": list(self.database_modifications),
            "event_rules": [dict(rule) for rule in self.event_rules],
        }


@dataclass(frozen=True)
class WebScope:
    allowed_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    allowed_schemes: tuple[str, ...] = ()
    forbidden_hosts: tuple[str, ...] = ()
    forbidden_ports: tuple[int, ...] = ()
    forbidden_schemes: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "WebScope":
        values = data or {}
        unknown = set(values) - set(cls.__dataclass_fields__)
        if unknown:
            warnings.warn(f"policy.scope: unknown fields ignored: {sorted(unknown)}")
        return cls(**{
            name: tuple(int(value) for value in values.get(name, ()))
            if name.endswith("ports") else tuple(values.get(name, ()))
            for name in cls.__dataclass_fields__
        })

    def to_dict(self) -> dict[str, list[Any]]:
        return {name: list(getattr(self, name)) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class Policy:
    schema_version: str = "0.1"
    allowed: AccessSet = field(default_factory=AccessSet)
    forbidden: AccessSet = field(default_factory=AccessSet)
    scope: WebScope = field(default_factory=WebScope)
    forbid_post_goal_requests: bool = False
    state_changing_methods: frozenset[str] = field(
        default_factory=lambda: _DEFAULT_STATE_CHANGING_METHODS
    )
    exempt_paths: frozenset[str] = field(default_factory=frozenset)
    roe: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        roe = data.get("roe") or {}
        if (
            "R2" in data
            and isinstance(roe, Mapping)
            and isinstance(roe.get("tool_authorization"), Mapping)
        ):
            raise ValueError(
                "ambiguous policy: use roe.tool_authorization, not top-level R2"
            )
        unknown = set(data) - _KNOWN_POLICY_KEYS
        if unknown:
            warnings.warn(f"policy: unknown fields ignored: {sorted(unknown)}")
        minimality = data.get("minimality") or {}
        return cls(
            schema_version=str(data.get("schema_version", "0.1")),
            allowed=AccessSet.from_dict(data.get("allowed")),
            forbidden=AccessSet.from_dict(data.get("forbidden")),
            scope=WebScope.from_dict(data.get("scope")),
            forbid_post_goal_requests=bool(
                minimality.get("forbid_post_goal_requests", False)
            ),
            state_changing_methods=frozenset(
                str(method).upper() for method in minimality.get(
                    "state_changing_methods", _DEFAULT_STATE_CHANGING_METHODS
                )
            ),
            exempt_paths=frozenset(
                str(path) for path in minimality.get("exempt_paths", ())
            ),
            roe=dict(roe) if isinstance(roe, Mapping) else {},
        )

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "allowed": self.allowed.to_dict(),
            "forbidden": self.forbidden.to_dict(),
            "scope": self.scope.to_dict(),
        }
        data["minimality"] = {
            "forbid_post_goal_requests": self.forbid_post_goal_requests,
            "state_changing_methods": sorted(self.state_changing_methods),
            "exempt_paths": sorted(self.exempt_paths),
        }
        if self.roe:
            data["roe"] = dict(self.roe)
        return data