import pytest

from agentic_soc.agent.llm import FakeLLM, LLMResponse
from agentic_soc.agent.metering import MeteredLLM
from agentic_soc.cost import Usage
from agentic_soc.evaluation import Case, Label, run_cases, summarize
from agentic_soc.models import Alert, RiskLevel, Verdict


def test_haiku_pricing() -> None:
    assert Usage(input_tokens=1_000_000).cost_usd("claude-haiku-4-5") == pytest.approx(1.00)
    assert Usage(output_tokens=1_000_000).cost_usd("claude-haiku-4-5") == pytest.approx(5.00)
    assert Usage(cache_write_tokens=1_000_000).cost_usd("claude-haiku-4-5") == pytest.approx(1.25)
    assert Usage(cache_read_tokens=1_000_000).cost_usd("claude-haiku-4-5") == pytest.approx(0.10)


def test_unknown_model_price_fails_loudly() -> None:
    with pytest.raises(ValueError):
        Usage(input_tokens=10).cost_usd("some-unpriced-model")


def test_meter_sums_calls_and_resets_on_take() -> None:
    reply = LLMResponse(text="x", usage=Usage(input_tokens=100, output_tokens=20))
    meter = MeteredLLM(FakeLLM(responses=[reply]))
    meter.complete([], [])
    meter.complete([], [])
    taken = meter.take()
    assert (taken.input_tokens, taken.output_tokens) == (200, 40)
    assert meter.take() == Usage()


def test_eval_attributes_usage_to_each_case() -> None:
    alert = Alert.model_validate(
        {"rule": {"id": "1", "level": 10, "description": "x"}, "agent": {"id": "000"}}
    )
    verdict = Verdict(risk_level=RiskLevel.HIGH, confidence=1.0, summary="s", root_cause="r")
    cases = [Case(alert=alert, label=Label.TRUE_POSITIVE, reason="r")] * 2
    results = run_cases(cases, lambda a: verdict, lambda: Usage(input_tokens=50, output_tokens=5))
    report = summarize(results)
    assert report.total_usage.input_tokens == 100
    assert report.total_usage.output_tokens == 10
