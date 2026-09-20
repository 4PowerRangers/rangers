"""Allowlisted command-tool definitions exposed to the agent runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    schema: dict[str, Any]
    execute: Callable[..., dict[str, Any]]


def _delegate(argv: list[str], timeout: float, executor: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    return executor(argv, timeout=timeout)


def build_tool_registry(executor: Callable[..., dict[str, Any]], selected_tools: list[str]) -> dict[str, ToolDefinition]:
    definitions = {
        "python3": ToolDefinition("python3", "Execute a Python script in the isolated agent container.", {
            "type": "object", "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "required": ["argv"], "additionalProperties": False,
        }, lambda argv, timeout: _delegate(argv, timeout, executor)),
        "curl": ToolDefinition("curl", "Make an HTTP request from the isolated agent container.", {
            "type": "object", "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "required": ["argv"], "additionalProperties": False,
        }, lambda argv, timeout: _delegate(argv, timeout, executor)),
        "bash": ToolDefinition("bash", "Run an argv command in the isolated agent container.", {
            "type": "object", "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "required": ["argv"], "additionalProperties": False,
        }, lambda argv, timeout: _delegate(argv, timeout, executor)),
        "sh": ToolDefinition("sh", "Run an argv command in the isolated agent container.", {
            "type": "object", "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "required": ["argv"], "additionalProperties": False,
        }, lambda argv, timeout: _delegate(argv, timeout, executor)),
        "nmap": ToolDefinition("nmap", "Inspect the configured target from the isolated agent container.", {
            "type": "object", "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
            "required": ["argv"], "additionalProperties": False,
        }, lambda argv, timeout: _delegate(argv, timeout, executor)),
    }
    unknown = [name for name in selected_tools if name not in definitions]
    if unknown:
        raise ValueError(f"Unknown command tools: {', '.join(unknown)}")
    return {name: definitions[name] for name in dict.fromkeys(selected_tools)}


def model_tool_schemas(registry: dict[str, ToolDefinition]) -> list[dict[str, Any]]:
    return [{"type": "function", "function": {"name": item.name, "description": item.description,
             "parameters": item.schema}} for item in registry.values()]