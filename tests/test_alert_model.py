from datetime import UTC, datetime
from pathlib import Path

from agentic_soc.models import Alert

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parses_invalid_user_alert() -> None:
    alert = Alert.model_validate_json(_load("ssh_invalid_user_5710.json"))
    assert alert.rule.id == "5710"
    assert alert.rule.level == 5
    assert alert.agent.id == "000"
    assert alert.data is not None
    assert alert.data.srcuser == "nosuchuser"
    assert alert.is_aggregated is False


def test_parses_bruteforce_alert() -> None:
    alert = Alert.model_validate_json(_load("ssh_bruteforce_5712.json"))
    assert alert.rule.id == "5712"
    assert alert.rule.level == 10
    assert alert.rule.frequency == 8
    assert alert.is_aggregated is True
    assert alert.previous_output is not None
    assert "T1110" in alert.mitre_techniques
    assert alert.source_ip == "192.168.64.2"


def test_tolerates_minimal_alert() -> None:
    alert = Alert.model_validate(
        {"rule": {"id": "1", "level": 3, "description": "x"}, "agent": {"id": "000"}}
    )
    assert alert.data is None
    assert alert.mitre_techniques == []
    assert alert.source_ip is None
    assert alert.is_aggregated is False


def test_occurred_at_converts_wazuh_timestamp_to_utc() -> None:
    alert = Alert.model_validate_json(_load("ssh_bruteforce_5712.json"))
    # Wazuh writes "2026-09-19T19:44:24.533-0500"; that is 00:44 UTC the next day.
    assert alert.occurred_at == datetime(2026, 9, 20, 0, 44, 24, 533000, tzinfo=UTC)


def test_occurred_at_is_none_when_missing_unreadable_or_without_offset() -> None:
    base = {"rule": {"id": "1", "level": 3, "description": "x"}, "agent": {"id": "000"}}
    for timestamp in (None, "not a time", "2026-09-19T19:44:24"):
        alert = Alert.model_validate({**base, "timestamp": timestamp})
        assert alert.occurred_at is None
