"""Factory for the read-only Wazuh tools the agent can call."""

from __future__ import annotations

import logging
from typing import Any

from agentic_soc.agent.tools import Tool
from agentic_soc.clients.indexer import IndexerClient

logger = logging.getLogger(__name__)


def make_search_alerts_tool(indexer: IndexerClient) -> Tool:
    def handler(arguments: dict[str, Any]) -> str:
        srcip = arguments.get("srcip")
        agent_id = arguments.get("agent_id")
        hours = int(arguments.get("hours", 24))
        alerts = indexer.search_alerts(srcip=srcip, agent_id=agent_id, hours=hours)
        logger.info(
            "tool search_alerts srcip=%s agent_id=%s hours=%s -> %d hits",
            srcip,
            agent_id,
            hours,
            len(alerts),
        )
        if not alerts:
            return "No matching alerts found in the window."
        lines: list[str] = []
        for alert in alerts:
            rule = alert.get("rule", {})
            lines.append(
                f"- {alert.get('timestamp', '?')} rule {rule.get('id')} "
                f"(level {rule.get('level')}): {rule.get('description')}"
            )
        return f"Found {len(alerts)} alert(s):\n" + "\n".join(lines)

    return Tool(
        name="search_alerts",
        description=(
            "Search recent Wazuh alerts to investigate context. Filter by source "
            "IP, Wazuh agent id, and/or a look-back window in hours."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "srcip": {"type": "string", "description": "Source IP to filter by"},
                "agent_id": {"type": "string", "description": "Wazuh agent id, e.g. 000"},
                "hours": {"type": "integer", "description": "Look back this many hours (default 24)"},
            },
        },
        handler=handler,
    )
