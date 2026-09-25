from agentic_soc.agent.anthropic_client import _to_anthropic
from agentic_soc.agent.llm import Message


def test_to_anthropic_splits_system_from_conversation() -> None:
    messages = [
        Message(role="system", content="you are an analyst"),
        Message(role="user", content="analyse this alert"),
    ]
    system, conversation = _to_anthropic(messages)
    assert system == "you are an analyst"
    assert conversation == [{"role": "user", "content": "analyse this alert"}]
