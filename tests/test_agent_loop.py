from agentic_soc.agent.llm import FakeLLM, LLMResponse, ToolCall
from agentic_soc.agent.loop import Budget, run_agent
from agentic_soc.agent.prompt import UNTRUSTED_OPEN, build_messages
from agentic_soc.agent.tools import Tool
from agentic_soc.models import Alert, RiskLevel

VERDICT_JSON = (
    '{"risk_level":"high","confidence":0.9,'
    '"summary":"Brute force from one source.",'
    '"root_cause":"Password guessing against sshd.",'
    '"mitre_techniques":["T1110"],'
    '"recommended_actions":["Block the IP"]}'
)


def _alert() -> Alert:
    return Alert.model_validate(
        {
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "brute force",
                "mitre": {"id": ["T1110"]},
            },
            "agent": {"id": "000", "name": "ryanyi"},
            "data": {"srcip": "192.168.64.2", "srcuser": "nosuchuser"},
            "full_log": "Failed password for invalid user nosuchuser",
        }
    )


def _search_tool(recorder):
    def handler(args):
        recorder.append(args)
        return "3 similar alerts in the last hour from the same IP."

    return Tool(
        name="search_alerts",
        description="Search recent alerts.",
        input_schema={"type": "object", "properties": {"srcip": {"type": "string"}}},
        handler=handler,
    )


def test_agent_investigates_then_returns_verdict() -> None:
    recorder: list = []
    tools = {"search_alerts": _search_tool(recorder)}
    llm = FakeLLM(
        responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="t1", name="search_alerts", arguments={"srcip": "192.168.64.2"})
                ]
            ),
            LLMResponse(text=VERDICT_JSON),
        ]
    )
    verdict = run_agent(_alert(), llm, tools)
    assert verdict.risk_level is RiskLevel.HIGH
    assert verdict.requires_attention is True
    assert recorder == [{"srcip": "192.168.64.2"}]  # the tool actually ran


def test_tool_call_budget_forces_degraded_verdict() -> None:
    always_tool = LLMResponse(tool_calls=[ToolCall(id="t", name="search_alerts", arguments={})])
    llm = FakeLLM(responses=[always_tool])
    tools = {"search_alerts": _search_tool([])}
    verdict = run_agent(_alert(), llm, tools, Budget(max_tool_calls=3))
    assert verdict.requires_attention is True  # degraded verdict never auto-suppresses
    assert verdict.confidence == 0.0


def test_unknown_tool_does_not_crash() -> None:
    llm = FakeLLM(
        responses=[
            LLMResponse(tool_calls=[ToolCall(id="t1", name="nope", arguments={})]),
            LLMResponse(text=VERDICT_JSON),
        ]
    )
    verdict = run_agent(_alert(), llm, {}, Budget())
    assert verdict.risk_level is RiskLevel.HIGH  # loop fed the error back and continued


def test_prompt_fences_untrusted_fields() -> None:
    messages = build_messages(_alert())
    user = messages[-1].content
    assert UNTRUSTED_OPEN in user
    assert "nosuchuser" in user.split(UNTRUSTED_OPEN, 1)[1]  # untrusted content is inside the fence
