from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_soc.context import EnvironmentContext, load_context
from agentic_soc.models import Alert, RiskLevel, Verdict

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parents[1]

CONTEXT = EnvironmentContext.model_validate(
    {
        "admins": [{"user": "ryanyi", "note": "Lab administrator."}],
        "trusted_networks": [{"cidr": "127.0.0.0/8", "note": "Loopback."}],
        "hosts": [{"agent_id": "000", "name": "ryanyi", "role": "Wazuh manager."}],
        "policies": [
            {
                "name": "brute-force-floor",
                "when": {"rule_groups_any": ["authentication_failures"], "aggregated": True},
                "min_risk": "high",
            },
            {
                "name": "external-login-success",
                "when": {
                    "rule_groups_any": ["authentication_success"],
                    "source_outside_trusted": True,
                },
                "min_risk": "high",
            },
        ],
    }
)


def _verdict(risk: RiskLevel) -> Verdict:
    return Verdict(risk_level=risk, confidence=0.9, summary="s", root_cause="r")


def _login(srcip: str, groups: list[str], user: str = "ryanyi") -> Alert:
    return Alert.model_validate(
        {
            "rule": {"id": "5715", "level": 3, "description": "login", "groups": groups},
            "agent": {"id": "000"},
            "data": {"srcip": srcip, "dstuser": user},
        }
    )


def _bruteforce() -> Alert:
    return Alert.model_validate_json((FIXTURES / "ssh_bruteforce_5712.json").read_text())


def test_notes_include_admin_host_and_trusted_source() -> None:
    text = " ".join(CONTEXT.notes_for(_login("127.0.0.1", ["authentication_failed"])))
    assert "known administrator" in text
    assert "Wazuh manager" in text
    assert "trusted network" in text


def test_no_admin_or_trust_notes_for_unknown_user_and_source() -> None:
    alert = _login("203.0.113.9", ["authentication_failed"], user="mallory")
    text = " ".join(CONTEXT.notes_for(alert))
    assert "known administrator" not in text
    assert "trusted network" not in text


def test_brute_force_floor_overrides_a_suppression() -> None:
    result = CONTEXT.apply_policies(_bruteforce(), _verdict(RiskLevel.FALSE_POSITIVE))
    assert result.risk_level is RiskLevel.HIGH
    assert result.applied_policies == ["brute-force-floor"]


def test_policies_never_lower_a_verdict() -> None:
    result = CONTEXT.apply_policies(_bruteforce(), _verdict(RiskLevel.CRITICAL))
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.applied_policies == []


def test_login_success_escalates_only_from_outside_trusted_networks() -> None:
    success = ["authentication_success"]
    outside = CONTEXT.apply_policies(_login("192.168.64.2", success), _verdict(RiskLevel.LOW))
    inside = CONTEXT.apply_policies(_login("127.0.0.1", success), _verdict(RiskLevel.LOW))
    assert outside.risk_level is RiskLevel.HIGH
    assert inside.risk_level is RiskLevel.LOW


def test_policy_without_conditions_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentContext.model_validate(
            {"policies": [{"name": "everything", "when": {}, "min_risk": "high"}]}
        )


def test_typo_in_context_file_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentContext.model_validate({"admins": [{"user": "ryanyi", "nots": "typo"}]})


def test_repo_context_file_is_valid() -> None:
    context = load_context(REPO / "context" / "infrastructure.yaml")
    assert {p.name for p in context.policies} >= {"brute-force-floor", "external-login-success"}
