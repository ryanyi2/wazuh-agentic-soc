"""Factory for the read-only Wazuh tools the agent can call."""

from __future__ import annotations

import logging
from typing import Any

from agentic_soc.agent.tools import Tool
from agentic_soc.clients.indexer import IndexerClient
from agentic_soc.models import Alert

logger = logging.getLogger(__name__)


def make_search_alerts_tool(indexer: IndexerClient) -> Tool:
    def handler(arguments: dict[str, Any], alert: Alert) -> str:
        srcip = arguments.get("srcip")
        agent_id = arguments.get("agent_id")
        hours = int(arguments.get("hours", 24))
        # The window ends when the alert fired, not now, so a replayed alert
        # never sees events that happened after it. Not a model argument.
        until = alert.occurred_at
        alerts = indexer.search_alerts(srcip=srcip, agent_id=agent_id, hours=hours, until=until)
        logger.info(
            "tool search_alerts srcip=%s agent_id=%s hours=%s until=%s -> %d hits",
            srcip,
            agent_id,
            hours,
            until.isoformat() if until else "now",
            len(alerts),
        )
        if not alerts:
            return "No matching alerts found in the window."
        lines: list[str] = []
        for hit in alerts:
            rule = hit.get("rule", {})
            lines.append(
                f"- {hit.get('timestamp', '?')} rule {rule.get('id')} "
                f"(level {rule.get('level')}): {rule.get('description')}"
            )
        return f"Found {len(alerts)} alert(s):\n" + "\n".join(lines)

    return Tool(
        name="search_alerts",
        description=(
            "Search the Wazuh alerts that fired in the hours before the alert under "
            "investigation. Filter by source IP and/or Wazuh agent id, and set how "
            "many hours to look back."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "srcip": {"type": "string", "description": "Source IP to filter by"},
                "agent_id": {"type": "string", "description": "Wazuh agent id, e.g. 000"},
                "hours": {
                    "type": "integer",
                    "description": "Hours to look back from when the alert fired (default 24)",
                },
            },
        },
        handler=handler,
    )
