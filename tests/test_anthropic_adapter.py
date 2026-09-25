from agentic_soc.agent.anthropic_client import _to_anthropic
from agentic_soc.agent.llm import Message, ToolCall


def test_to_anthropic_splits_system_from_conversation() -> None:
    messages = [
        Message(role="system", content="you are an analyst"),
        Message(role="user", content="analyse this alert"),
    ]
    system, conversation = _to_anthropic(messages)
    assert system == "you are an analyst"
    assert conversation == [{"role": "user", "content": "analyse this alert"}]


def test_to_anthropic_threads_tool_use_and_result() -> None:
    messages = [
        Message(role="user", content="analyse"),
        Message(
            role="assistant",
            content="",
            tool_calls=[ToolCall(id="t1", name="search_alerts", arguments={"srcip": "1.2.3.4"})],
        ),
        Message(role="tool", content="found 2 alerts", tool_call_id="t1"),
    ]
    _, conversation = _to_anthropic(messages)
    assert conversation[1]["role"] == "assistant"
    assert conversation[1]["content"][0]["type"] == "tool_use"
    assert conversation[2]["role"] == "user"
    assert conversation[2]["content"][0]["type"] == "tool_result"
    assert conversation[2]["content"][0]["tool_use_id"] == "t1"
