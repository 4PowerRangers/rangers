import json
from typing import Any, Callable, Mapping

from .base import AgentContext, AgentMetadata, AgentProposal, AgentProviderError, MalformedAgentAction


class InternalLLMAgentAdapter:
    def __init__(self, *, mission: str, provider: str | None, model: str | None,
                 temperature: float | None, seed: int | None,
                 max_tokens: int | None = None,
                 call: Callable[..., str], parse: Callable[[str], dict[str, Any] | None],
                 agent_version: str = "poc",
                 available_tools: tuple[str, ...] | list[str] = (),
                 tool_schemas: list[dict[str, Any]] | None = None) -> None:
        self.mission = mission
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.seed = seed
        self.max_tokens = max_tokens
        self._call = call
        self._parse = parse
        self._messages: list[dict[str, str]] = []
        self._last_raw: str | None = None
        self._metadata = AgentMetadata(
            adapter_name="internal-llm",
            adapter_version="1",
            agent_name="tempera-internal-agent",
            agent_version=agent_version,
            provider=provider,
            model=model,
            declared_capabilities=("http_request", "run_tool"),
        )
        self.available_tools = tuple(available_tools)
        self.tool_schemas = list(tool_schemas or [])

    def metadata(self) -> AgentMetadata:
        return self._metadata

    def prepare(self, context: AgentContext) -> None:
        self._messages = [
            {"role": "system", "content": self.mission + self._tool_contract() + self._schema_contract()},
            {"role": "user", "content": "Start. Print your first action in JSON."},
        ]

    def _schema_contract(self) -> str:
        if not self.tool_schemas:
            return ""
        return "\nSelected command tool schemas:\n" + json.dumps(self.tool_schemas, ensure_ascii=False)

    def _tool_contract(self) -> str:
        tools = ", ".join(self.available_tools) or "None"
        return (
            "\nAvailable Kali executables (actual PATH): " + tools
            + "\nSelect command actions only when necessary. Use the argv array instead of a shell string."
            + "\nrun_tool format: {\"action\":\"run_tool\",\"argv\":[\"curl\",\"...\"]}"
        )

    def next_action(self, context: AgentContext) -> AgentProposal:
        capability = context.runtime.get("capability_v2")
        if isinstance(capability, Mapping):
            self._messages.append({
                "role": "user",
                "content": "[planner and working memory]\n"
                + json.dumps(capability, ensure_ascii=False, default=str)
                + "\nUse this bounded state to choose the next action. Output exactly one JSON object.",
            })
        try:
            raw_text = self._call(
                self._messages, provider=self.provider, model=self.model,
                temperature=self.temperature, seed=self.seed, max_tokens=self.max_tokens,
            )
        except Exception as exc:
            raise AgentProviderError(f"{type(exc).__name__}: {exc}") from exc
        self._last_raw = raw_text
        action = self._parse(raw_text)
        if not action:
            raise MalformedAgentAction("provider output did not contain an action object")
        return AgentProposal(
            agent_id=self._metadata.agent_name,
            step=context.step,
            raw=action,
            tool={"name": action.get("action", "unknown")},
            arguments=action,
            reasoning=action.get("thought"),
            raw_text=raw_text,
        )

    def receive_observation(self, observation: Any) -> None:
        self._messages.extend([
            {"role": "assistant", "content": self._last_raw or ""},
            {"role": "user", "content": f"[Observation]\n{observation}\n\nOutput the next action in JSON."},
        ])

    def finalize(self) -> Mapping[str, Any]:
        return {"status": "completed"}