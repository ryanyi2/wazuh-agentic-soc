import json

import pytest
from pydantic import ValidationError

from agentic_soc.models import RiskLevel, Verdict


def test_verdict_serializes_to_expected_json() -> None:
    verdict = Verdict(
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        summary="Sustained SSH brute force from a single source.",
        root_cause="Automated password guessing against an exposed sshd.",
        mitre_techniques=["T1110"],
        recommended_actions=["Confirm no successful login", "Block the source IP"],
    )
    assert verdict.requires_attention is True
    dumped = json.loads(verdict.model_dump_json())
    assert dumped["risk_level"] == "high"
    assert dumped["mitre_techniques"] == ["T1110"]


def test_false_positive_does_not_require_attention() -> None:
    verdict = Verdict(
        risk_level=RiskLevel.FALSE_POSITIVE,
        confidence=0.8,
        summary="Benign scanner activity.",
        root_cause="Scheduled vulnerability scan from a known host.",
    )
    assert verdict.requires_attention is False


def test_confidence_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        Verdict(risk_level=RiskLevel.LOW, confidence=1.5, summary="x", root_cause="y")


def test_invalid_risk_level_rejected() -> None:
    with pytest.raises(ValidationError):
        Verdict(risk_level="apocalyptic", confidence=0.5, summary="x", root_cause="y")  # type: ignore[arg-type]
