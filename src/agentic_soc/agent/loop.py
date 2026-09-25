"""The bounded agent loop: think -> call a tool -> read result -> answer.

Synchronous and pure so it can be tested deterministically; the async worker
offloads it with asyncio.to_thread. Two independent guards (a tool-call cap and
a wall-clock deadline) guarantee termination. On budget exhaustion or an
unparseable answer it returns a degraded verdict that escalates for human
review — it never silently suppresses an alert it could not finish analysing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from agentic_soc.agent.llm import LLMClient, Message, ToolCall
from agentic_soc.agent.prompt import build_messages
from agentic_soc.agent.tools import Tool
from agentic_soc.models import Alert, RiskLevel, Verdict


@dataclass
class Budget:
    max_tool_calls: int = 8
    max_seconds: float = 60.0


def _degraded_verdict(reason: str) -> Verdict:
    return Verdict(
        risk_level=RiskLevel.MEDIUM,
        confidence=0.0,
        summary="Analysis did not complete; escalating for human review.",
        root_cause=reason,
        recommended_actions=["Review this alert manually."],
    )


def _dispatch(call: ToolCall, tools: dict[str, Tool]) -> str:
    tool = tools.get(call.name)
    if tool is None:
        return f"error: unknown tool {call.name!r}"
    try:
        return tool.run(call.arguments)
    except Exception as exc:  # a tool failure must not crash the loop
        return f"error: {exc}"


def _parse_verdict(text: str | None) -> Verdict:
    if not text:
        return _degraded_verdict("Model returned no final answer.")
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return _degraded_verdict("Model's final answer contained no JSON object.")
    try:
        return Verdict.model_validate_json(text[start : end + 1])
    except ValueError:
        return _degraded_verdict("Model's final answer was not a valid verdict.")


def run_agent(
    alert: Alert,
    llm: LLMClient,
    tools: dict[str, Tool],
    budget: Budget | None = None,
) -> Verdict:
    budget = budget or Budget()
    specs = [tool.spec for tool in tools.values()]
    messages = list(build_messages(alert))
    started = time.monotonic()
    tool_calls_made = 0

    while True:
        if time.monotonic() - started > budget.max_seconds:
            return _degraded_verdict("Wall-clock budget exhausted.")
        response = llm.complete(messages, specs)
        if not response.tool_calls:
            return _parse_verdict(response.text)
        messages.append(
            Message(role="assistant", content=response.text or "", tool_calls=response.tool_calls)
        )
        for call in response.tool_calls:
            if tool_calls_made >= budget.max_tool_calls:
                return _degraded_verdict("Tool-call budget exhausted.")
            result = _dispatch(call, tools)
            tool_calls_made += 1
            messages.append(Message(role="tool", content=result, tool_call_id=call.id))
