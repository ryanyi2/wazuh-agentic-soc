"""Typed, tolerant model of the Wazuh alert envelope.

Wazuh alerts are semi-structured and vary by rule: aggregated rules carry
``frequency`` and ``previous_output``; file-integrity alerts carry ``syscheck``;
many alerts have no ``data`` block at all. This model therefore treats almost
every field as optional and ignores unknown fields, so a differently-shaped
alert is parsed, not rejected.

Security note: ``full_log``, ``data.srcuser`` and ``data.srcip`` are
attacker-influenced — an adversary picks the username they try and the traffic
they send. Those values are captured here as plain data; they are fenced as
untrusted input at the prompt layer, never trusted to steer the analyzer.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class Mitre(BaseModel):
    """MITRE ATT&CK mapping Wazuh attaches to a rule."""

    model_config = ConfigDict(extra="ignore")

    id: list[str] = Field(default_factory=list)
    tactic: list[str] = Field(default_factory=list)
    technique: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    """The rule that fired, including severity and MITRE mapping."""

    model_config = ConfigDict(extra="ignore")

    id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)
    firedtimes: int | None = None
    frequency: int | None = None
    mitre: Mitre | None = None


class Agent(BaseModel):
    """The Wazuh agent (monitored host) the alert came from."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str | None = None
    ip: str | None = None


class AlertData(BaseModel):
    """Decoded fields. Contents vary by decoder; extras are preserved."""

    model_config = ConfigDict(extra="allow")

    srcip: str | None = None
    srcport: str | None = None
    srcuser: str | None = None
    dstuser: str | None = None


class Alert(BaseModel):
    """A single Wazuh alert as written to alerts.json."""

    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    timestamp: str | None = None
    rule: Rule
    agent: Agent
    location: str | None = None
    full_log: str | None = None
    previous_output: str | None = None
    data: AlertData | None = None

    @property
    def is_aggregated(self) -> bool:
        """True when Wazuh correlated several events into this one alert."""
        return self.rule.frequency is not None or self.previous_output is not None

    @property
    def source_ip(self) -> str | None:
        """Source IP, if the decoder extracted one."""
        return self.data.srcip if self.data else None

    @property
    def occurred_at(self) -> datetime | None:
        """When the alert fired, in UTC. None if the timestamp is missing or unreadable."""
        if not self.timestamp:
            return None
        try:
            parsed = datetime.fromisoformat(self.timestamp)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None  # no offset: refuse to guess a timezone
        return parsed.astimezone(UTC)

    @property
    def mitre_techniques(self) -> list[str]:
        """MITRE technique IDs on the rule, e.g. ['T1110']."""
        return list(self.rule.mitre.id) if self.rule.mitre else []
