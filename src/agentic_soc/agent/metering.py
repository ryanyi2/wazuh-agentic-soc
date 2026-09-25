"""A metering wrapper: counts tokens across every model call for one alert.

It implements the same LLMClient interface as the real client, so the agent
loop is unchanged and doesn't know it is being measured. The eval harness calls
take() after each case to collect that case's usage and reset the counters.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from agentic_soc.agent.llm import LLMClient, LLMResponse, Message, ToolSpec
from agentic_soc.cost import Usage


@dataclass
class MeteredLLM:
    inner: LLMClient
    usage: Usage = field(default_factory=Usage)

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMResponse:
        response = self.inner.complete(messages, tools)
        self.usage.add(response.usage)
        return response

    def take(self) -> Usage:
        """Return usage since the last take() and reset the counters."""
        taken, self.usage = self.usage, Usage()
        return taken
