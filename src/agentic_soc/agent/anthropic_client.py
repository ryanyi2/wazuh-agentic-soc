"""Anthropic adapter: implements the LLMClient interface using Claude.

Translates the loop's provider-agnostic messages to and from the Anthropic
Messages API, including the tool_use / tool_result threading a real tool call
requires. Isolated so nothing else imports the vendor SDK.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

import anthropic

from agentic_soc.agent.llm import LLMResponse, Message, ToolCall, ToolSpec
from agentic_soc.cost import Usage


def _to_anthropic(messages: Sequence[Message]) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    conversation: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "system":
            system_parts.append(msg.content)
        elif msg.role == "user":
            conversation.append({"role": "user", "content": msg.content})
        elif msg.role == "assistant":
            blocks: list[dict[str, Any]] = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            for call in msg.tool_calls:
                blocks.append(
                    {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
                )
            conversation.append({"role": "assistant", "content": blocks})
        elif msg.role == "tool":
            block = {
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id,
                "content": msg.content,
            }
            if (
                conversation
                and conversation[-1]["role"] == "user"
                and isinstance(conversation[-1]["content"], list)
            ):
                conversation[-1]["content"].append(block)
            else:
                conversation.append({"role": "user", "content": [block]})
    return "\n".join(system_parts), conversation


def _from_anthropic(response: anthropic.types.Message) -> LLMResponse:
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in response.content:
        if isinstance(block, anthropic.types.TextBlock):
            text_parts.append(block.text)
        elif isinstance(block, anthropic.types.ToolUseBlock):
            arguments = cast("dict[str, Any]", block.input)
            tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=arguments))
    usage = Usage(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        cache_write_tokens=response.usage.cache_creation_input_tokens or 0,
        cache_read_tokens=response.usage.cache_read_input_tokens or 0,
    )
    return LLMResponse(text="\n".join(text_parts) or None, tool_calls=tool_calls, usage=usage)


class AnthropicLLM:
    """LLMClient backed by the Anthropic Messages API (default: Claude Haiku 4.5).

    Current Claude models don't accept sampling parameters such as temperature,
    so the same alert can get a different verdict on different runs. The eval
    harness measures that variation with repeated runs instead of hiding it.
    """

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
