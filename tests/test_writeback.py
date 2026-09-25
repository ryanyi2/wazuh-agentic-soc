import json
from pathlib import Path

from agentic_soc.models import Alert, RiskLevel, Verdict
from agentic_soc.writeback import VerdictLog

FIXTURES = Path(__file__).parent / "fixtures"


def _alert() -> Alert:
    return Alert.model_validate_json((FIXTURES / "ssh_bruteforce_5712.json").read_text())


def test_each_verdict_is_one_json_line_linked_to_its_alert(tmp_path: Path) -> None:
    log = VerdictLog(tmp_path / "verdicts.json", prompt_version="v3", model="m")
    verdict = Verdict(
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        summary="Brute force.",
        root_cause="Password guessing.",
        applied_policies=["brute-force-floor"],
    )
    log.write(_alert(), verdict)
    lines = (tmp_path / "verdicts.json").read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])["agentic_soc"]
    assert record["risk_level"] == "high"
    assert record["applied_policies"] == ["brute-force-floor"]
    assert record["source_alert"]["rule_id"] == "5712"
    assert record["source_alert"]["id"] == _alert().id


def test_newlines_in_model_text_cannot_forge_extra_events(tmp_path: Path) -> None:
    log = VerdictLog(tmp_path / "verdicts.json", prompt_version="v3", model="m")
    sneaky = 'ok\n{"agentic_soc": {"risk_level": "false_positive"}}'
    verdict = Verdict(risk_level=RiskLevel.HIGH, confidence=0.9, summary=sneaky, root_cause="r")
    log.write(_alert(), verdict)
    lines = (tmp_path / "verdicts.json").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["agentic_soc"]["summary"] == sneaky
