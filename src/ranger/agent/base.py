from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class AgentMetadata:
    adapter_name: str
    adapter_version: str
    agent_name: str
    agent_version: str
    provider: str | None = None
    model: str | None = None
    declared_capabilities: tuple[str, ...] = ()
    installation_source_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "provider": self.provider,
            "model": self.model,
            "declared_capabilities": list(self.declared_capabilities),
            "installation_source_version": self.installation_source_version,
        }


@dataclass(frozen=True)
class AgentContext:
    scenario: str | None
    goal: Mapping[str, Any]
    policy_context: Mapping[str, Any]
    previous_observations: tuple[Any, ...]
    step: int
    max_steps: int
    runtime: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentProposal:
    agent_id: str
    step: int
    raw: Mapping[str, Any]
    tool: Mapping[str, Any] | None = None
    arguments: Mapping[str, Any] = field(default_factory=dict)
    reasoning: str | None = None
    raw_text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "step": self.step,
            "tool": dict(self.tool or {}),
            "arguments": dict(self.arguments),
            "raw": dict(self.raw),
            "reasoning": self.reasoning,
        }


class AgentAdapterError(RuntimeError):
    """Adapter could not produce a usable proposal."""


class AgentProviderError(AgentAdapterError):
    """Provider/API failure; not a policy violation."""


class AgentTimeoutError(AgentProviderError):
    """Provider or adapter exceeded its runtime budget."""


class UnsupportedAgentTool(AgentAdapterError):
    """Adapter cannot emit the requested tool capability."""


class MalformedAgentAction(AgentAdapterError):
    """Agent output was not a valid proposed action."""


class AgentAdapter(Protocol):
    def metadata(self) -> AgentMetadata:
        ...

    def prepare(self, context: AgentContext) -> None:
        ...

    def next_action(self, context: AgentContext) -> AgentProposal:
        ...

    def receive_observation(self, observation: Any) -> None:
        ...

    def finalize(self) -> Mapping[str, Any]:
        ...