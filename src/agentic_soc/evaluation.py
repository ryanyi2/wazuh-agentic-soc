"""Evaluation harness: score the agent's verdicts against labelled alerts.

A labelled case pairs a real Wazuh alert with a ground-truth label
(true_positive or false_positive) and a human reason. The harness runs the agent
over each case and reports the metrics that matter for triage: how much volume
it removes, how often it is right when it suppresses, and — the cardinal safety
metric, tracked on its own — how many real threats it wrongly suppressed.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from agentic_soc.models import Alert, Verdict


class Label(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Case:
    alert: Alert
    label: Label
    reason: str


@dataclass
class CaseResult:
    case: Case
    verdict: Verdict
    latency_seconds: float

    @property
    def suppressed(self) -> bool:
        return not self.verdict.requires_attention

    @property
    def is_benign(self) -> bool:
        return self.case.label is Label.FALSE_POSITIVE

    @property
    def missed_threat(self) -> bool:
        # The cardinal error: suppressed something that was actually an attack.
        return self.suppressed and not self.is_benign


@dataclass
class Report:
    total: int
    suppressed: int
    correct_suppressions: int
    missed_threats: int
    caught_threats: int
    benign_total: int
    mean_latency_seconds: float

    @property
    def suppression_precision(self) -> float:
        if self.suppressed == 0:
            return 1.0
        return self.correct_suppressions / self.suppressed

    @property
    def suppression_recall(self) -> float:
        if self.benign_total == 0:
            return 0.0
        return self.correct_suppressions / self.benign_total

    @property
    def triage_reduction(self) -> float:
        if self.total == 0:
            return 0.0
        return self.suppressed / self.total


def summarize(results: Sequence[CaseResult]) -> Report:
    total = len(results)
    suppressed = sum(1 for r in results if r.suppressed)
    correct = sum(1 for r in results if r.suppressed and r.is_benign)
    missed = sum(1 for r in results if r.missed_threat)
    caught = sum(1 for r in results if not r.suppressed and not r.is_benign)
    benign_total = sum(1 for r in results if r.is_benign)
    mean_latency = sum(r.latency_seconds for r in results) / total if total else 0.0
    return Report(
        total=total,
        suppressed=suppressed,
        correct_suppressions=correct,
        missed_threats=missed,
        caught_threats=caught,
        benign_total=benign_total,
        mean_latency_seconds=mean_latency,
    )


def run_cases(cases: Iterable[Case], run: Callable[[Alert], Verdict]) -> list[CaseResult]:
    results: list[CaseResult] = []
    for case in cases:
        started = time.monotonic()
        verdict = run(case.alert)
        latency = time.monotonic() - started
        results.append(CaseResult(case=case, verdict=verdict, latency_seconds=latency))
    return results


def evaluate(cases: Iterable[Case], run: Callable[[Alert], Verdict]) -> Report:
    return summarize(run_cases(cases, run))


def load_cases(path: Path) -> list[Case]:
    cases: list[Case] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        cases.append(
            Case(
                alert=Alert.model_validate(record["alert"]),
                label=Label(record["label"]),
                reason=record["reason"],
            )
        )
    return cases
