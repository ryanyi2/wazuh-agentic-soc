"""Environment context: trusted facts about this environment, plus hard policy.

Two jobs, deliberately kept separate:

1. Facts for the model. Written by the defenders: who the admins are, which
   networks are trusted, what each host is. Only entries relevant to an alert
   are sent to the model, so the prompt stays small as this file grows. Entries
   state facts, not verdicts, so the model still has to reason.

2. Policy in code. Rules that set a minimum risk level, applied after the model
   answers. They can only raise a verdict, never lower it: a model can be talked
   out of things, an if statement cannot. Policies never suppress on their own,
   because an auto-suppress rule is a blind spot an attacker can aim for, while
   an escalation rule can only cost an analyst some time.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, IPvAnyNetwork, model_validator

from agentic_soc.models import Alert, RiskLevel, Verdict

_RISK_ORDER = [
    RiskLevel.FALSE_POSITIVE,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
]


def _rank(level: RiskLevel) -> int:
    return _RISK_ORDER.index(level)


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


class Admin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: str
    note: str = ""


class TrustedNetwork(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: IPvAnyNetwork
    note: str = ""


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    name: str = ""
    role: str = ""


class PolicyCondition(BaseModel):
    """Every condition that is set must match. At least one must be set."""

    model_config = ConfigDict(extra="forbid")

    rule_groups_any: list[str] = Field(default_factory=list)
    aggregated: bool | None = None
    source_outside_trusted: bool | None = None

    @model_validator(mode="after")
    def _require_a_condition(self) -> PolicyCondition:
        if (
            not self.rule_groups_any
            and self.aggregated is None
            and self.source_outside_trusted is None
        ):
            raise ValueError("a policy must set at least one condition")
        return self


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    when: PolicyCondition
    min_risk: RiskLevel


class EnvironmentContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    admins: list[Admin] = Field(default_factory=list)
    trusted_networks: list[TrustedNetwork] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    policies: list[Policy] = Field(default_factory=list)

    def is_trusted_source(self, ip: str | None) -> bool:
        address = _parse_ip(ip)
        if address is None:
            return False
        return any(address in net.cidr for net in self.trusted_networks)

    def notes_for(self, alert: Alert) -> list[str]:
        """Facts relevant to this alert, for the model's trusted context block."""
        notes: list[str] = []
        users: set[str] = set()
        if alert.data:
            for candidate in (alert.data.srcuser, alert.data.dstuser):
                if candidate:
                    users.add(candidate)
        for admin in self.admins:
            if admin.user in users:
                notes.append(
                    f"User '{admin.user}' is a known administrator. {admin.note}".strip()
                )
        for host in self.hosts:
            if host.agent_id == alert.agent.id:
                notes.append(f"Agent {host.agent_id} ({host.name}): {host.role}".strip())
        address = _parse_ip(alert.source_ip)
        if address is not None:
            for net in self.trusted_networks:
                if address in net.cidr:
                    notes.append(
                        f"Source {address} is inside trusted network {net.cidr}. {net.note}".strip()
                    )
        return notes

    def _matches(self, condition: PolicyCondition, alert: Alert) -> bool:
        groups = set(alert.rule.groups)
        if condition.rule_groups_any and not groups.intersection(condition.rule_groups_any):
            return False
        if condition.aggregated is not None and alert.is_aggregated != condition.aggregated:
            return False
        if condition.source_outside_trusted is not None:
            outside = alert.source_ip is not None and not self.is_trusted_source(alert.source_ip)
            if outside != condition.source_outside_trusted:
                return False
        return True

    def apply_policies(self, alert: Alert, verdict: Verdict) -> Verdict:
        """Raise the verdict to any matching policy's floor. Never lowers it."""
        risk = verdict.risk_level
        applied: list[str] = []
        for policy in self.policies:
            if self._matches(policy.when, alert) and _rank(policy.min_risk) > _rank(risk):
                risk = policy.min_risk
                applied.append(policy.name)
        if not applied:
            return verdict
        return verdict.model_copy(
            update={
                "risk_level": risk,
                "applied_policies": [*verdict.applied_policies, *applied],
            }
        )


def load_context(path: Path) -> EnvironmentContext:
    """Load and validate a context file. safe_load never constructs Python objects."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return EnvironmentContext.model_validate(raw)
