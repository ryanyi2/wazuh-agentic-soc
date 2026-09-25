"""Tools the agent may call. Each tool is read-only by construction.

A Tool pairs a schema (advertised to the model) with a handler that executes it.
The loop only dispatches to tools in its registry, so the model can name a tool
but can never invoke code that was not explicitly registered.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentic_soc.agent.llm import ToolSpec


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], str]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            input_schema=self.input_schema,
        )

    def run(self, arguments: dict[str, Any]) -> str:
        return self.handler(arguments)
