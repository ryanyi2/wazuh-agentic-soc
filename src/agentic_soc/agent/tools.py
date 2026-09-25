"""Tools the agent may call. Each tool is read-only by construction.

A Tool pairs a schema (advertised to the model) with a handler that executes it.
The loop only dispatches to tools in its registry, so the model can name a tool
but can never invoke code that was not explicitly registered.

Handlers also receive the alert under investigation, passed by the loop rather
than by the model. The model chooses what to search for; facts it must not
control, such as when the alert fired, come from the alert itself.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentic_soc.agent.llm import ToolSpec
from agentic_soc.models import Alert


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any], Alert], str]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            input_schema=self.input_schema,
        )

    def run(self, arguments: dict[str, Any], alert: Alert) -> str:
        return self.handler(arguments, alert)
