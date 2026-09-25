"""Read-only client for the Wazuh Indexer (OpenSearch).

Structurally read-only: the only request it issues is a POST to the _search
endpoint of the wazuh-alerts indices. There is no method that indexes, updates,
or deletes, so the analyzer cannot mutate the SIEM through it. The read-only
guarantee is enforced by this class's surface, not by trust.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx


class IndexerClient:
    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            auth=(user, password),
            verify=verify_tls,
            timeout=timeout,
            transport=transport,
        )

    def search_alerts(
        self,
        *,
        srcip: str | None = None,
        agent_id: str | None = None,
        rule_id: str | None = None,
        hours: int = 24,
        size: int = 10,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        must: list[dict[str, Any]] = [{"range": {"timestamp": _window(hours, until)}}]
        if srcip:
            must.append({"term": {"data.srcip": srcip}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if rule_id:
            must.append({"term": {"rule.id": rule_id}})
        body = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}},
        }
        response = self._client.post("/wazuh-alerts-*/_search", json=body)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]


def _window(hours: int, until: datetime | None) -> dict[str, str]:
    """The `hours` before `until`, or before now when no anchor is given.

    Anchoring matters when replaying an old alert: a window relative to now
    would include events that happened after the alert fired.
    """
    if until is None:
        return {"gte": f"now-{hours}h"}
    start = until - timedelta(hours=hours)
    return {
        "gte": start.isoformat(timespec="milliseconds"),
        "lte": until.isoformat(timespec="milliseconds"),
        "format": "strict_date_optional_time",
    }
