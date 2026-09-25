"""Anthropic adapter: implements the LLMClient interface using Claude.

Isolates the vendor SDK so the rest of the codebase depends only on the small
provider-agnostic types in agent.llm. Swapping providers means adding another
file like this one, and changing nothing else.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

import anthropic

from agentic_soc.agent.llm import LLMResponse, Message, ToolCall, ToolSpec


def _to_anthropic(messages: Sequence[Message]) -> tuple[str, list[dict[str, Any]]]:
    """Split system text out and turn the rest into Anthropic message dicts."""
    system_parts: list[str] = []
    conversation: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "system":
            system_parts.append(msg.content)
        else:
            conversation.append({"role": msg.role, "content": msg.content})
    return "\n".join(system_parts), conversation


def _from_anthropic(response: anthropic.types.Message) -> LLMResponse:
    """Turn an Anthropic response into our provider-agnostic LLMResponse."""
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in response.content:
        if isinstance(block, anthropic.types.TextBlock):
            text_parts.append(block.text)
        elif isinstance(block, anthropic.types.ToolUseBlock):
            tool_calls.append(
                ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=cast("dict[str, Any]", block.input),
                )
            )
    return LLMResponse(text="\n".join(text_parts) or None, tool_calls=tool_calls)


class AnthropicLLM:
    """LLMClient backed by the Anthropic Messages API (default: Claude Haiku 4.5)."""

    def __init__(
        self, api_key: str, model: str = "claude-haiku-4-5", max_tokens: int = 2048
    ) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMResponse:
        system, conversation = _to_anthropic(messages)
        api_tools = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in tools
        ]
        if api_tools:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system,
                messages=cast("list[Any]", conversation),
                tools=cast("list[Any]", api_tools),
            )
        else:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system,
                messages=cast("list[Any]", conversation),
            )
        return _from_anthropic(response)
