"""Writeback: record every verdict as one JSON line that Wazuh ingests.

The service never writes into Wazuh's internals. It appends to its own log file,
and Wazuh reads that file through a <localfile> with log_format json, the same
way it reads any other log source. That keeps the service least-privilege (no
access to Wazuh's sockets or queues) and leaves an on-disk audit trail of every
verdict, including the ones the agent cleared.

json.dumps escapes newlines and non-ASCII characters, so each verdict is exactly
one line: model text containing a newline cannot forge a second event.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_soc.models import Alert, Verdict


def verdict_record(
    alert: Alert, verdict: Verdict, *, prompt_version: str, model: str
) -> dict[str, Any]:
    return {
        "agentic_soc": {
            "risk_level": verdict.risk_level.value,
            "confidence": verdict.confidence,
            "summary": verdict.summary,
            "root_cause": verdict.root_cause,
            "mitre_techniques": verdict.mitre_techniques,
            "recommended_actions": verdict.recommended_actions,
            "applied_policies": verdict.applied_policies,
            "prompt_version": prompt_version,
            "model": model,
            "analyzed_at": datetime.now(UTC).isoformat(),
            "source_alert": {
                "id": alert.id,
                "rule_id": alert.rule.id,
                "rule_level": alert.rule.level,
                "rule_description": alert.rule.description,
                "agent_id": alert.agent.id,
                "agent_name": alert.agent.name,
                "timestamp": alert.timestamp,
            },
        }
    }


class VerdictLog:
    """Append-only JSON-lines file that Wazuh reads with log_format json."""

    def __init__(self, path: Path, *, prompt_version: str, model: str) -> None:
        self._path = path
        self._prompt_version = prompt_version
        self._model = model
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, alert: Alert, verdict: Verdict) -> None:
        record = verdict_record(
            alert, verdict, prompt_version=self._prompt_version, model=self._model
        )
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
