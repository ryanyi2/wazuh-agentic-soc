"""Provider-agnostic LLM interface for the agent loop.

The loop is written against these small types, not against any vendor SDK. A
concrete adapter (Anthropic) translates them to and from a real API, and a
FakeLLM implements the same interface for deterministic tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None


@dataclass
class LLMResponse:
    text: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient(Protocol):
    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMResponse: ...


@dataclass
class FakeLLM:
    """Scripted LLM for tests: returns queued responses in order, repeating the last."""

    responses: list[LLMResponse]
    calls: int = 0

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMResponse:
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return response
