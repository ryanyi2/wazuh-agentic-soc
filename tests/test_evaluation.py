from agentic_soc.evaluation import Case, Label, evaluate
from agentic_soc.models import Alert, RiskLevel, Verdict


def _alert(rule_id: str) -> Alert:
    return Alert.model_validate(
        {"rule": {"id": rule_id, "level": 10, "description": "x"}, "agent": {"id": "000"}}
    )


def _verdict(risk: RiskLevel) -> Verdict:
    return Verdict(risk_level=risk, confidence=1.0, summary="s", root_cause="r")


def test_suppressing_a_real_threat_is_counted_as_missed() -> None:
    cases = [
        Case(alert=_alert("5712"), label=Label.TRUE_POSITIVE, reason="attack"),
        Case(alert=_alert("1002"), label=Label.FALSE_POSITIVE, reason="benign"),
    ]
    report = evaluate(cases, lambda a: _verdict(RiskLevel.FALSE_POSITIVE))
    assert report.suppressed == 2
    assert report.missed_threats == 1  # suppressed the real attack: the cardinal error
    assert report.suppression_precision == 0.5
    assert report.triage_reduction == 1.0
    assert report.suppression_recall == 1.0


def test_escalating_everything_misses_no_threats() -> None:
    cases = [
        Case(alert=_alert("5712"), label=Label.TRUE_POSITIVE, reason="attack"),
        Case(alert=_alert("1002"), label=Label.FALSE_POSITIVE, reason="benign"),
    ]
    report = evaluate(cases, lambda a: _verdict(RiskLevel.HIGH))
    assert report.missed_threats == 0
    assert report.caught_threats == 1
    assert report.suppressed == 0
    assert report.suppression_precision == 1.0
    assert report.suppression_recall == 0.0
