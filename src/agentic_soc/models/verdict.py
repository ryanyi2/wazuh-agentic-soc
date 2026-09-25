"""The structured verdict the agent must produce for each alert.

Forcing the model to return typed fields instead of prose is what makes its
output usable by code: we can route on risk_level, write the verdict back into
Wazuh, and score it against a labelled set. Pydantic validates the shape, so a
malformed model response is rejected here rather than silently mishandled.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FALSE_POSITIVE = "false_positive"


class Verdict(BaseModel):
    """The agent's structured conclusion about one alert."""

    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str  # one-sentence verdict in plain English
    root_cause: str  # what most likely happened
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    # Names of code-enforced policies that raised this verdict (see agentic_soc.context).
    applied_policies: list[str] = Field(default_factory=list)

    @property
    def requires_attention(self) -> bool:
        """False only when the analyst concluded the alert is a false positive."""
        return self.risk_level is not RiskLevel.FALSE_POSITIVE
