import json
from pathlib import Path
from typing import Any

import httpx

from agentic_soc.agent.wazuh_tools import make_search_alerts_tool
from agentic_soc.clients.indexer import IndexerClient
from agentic_soc.models import Alert

FIXTURES = Path(__file__).parent / "fixtures"


def _tool_and_bodies() -> tuple[Any, list[dict[str, Any]]]:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"hits": {"hits": []}})

    indexer = IndexerClient("https://x", "u", "p", transport=httpx.MockTransport(handler))
    return make_search_alerts_tool(indexer), bodies


def _window(body: dict[str, Any]) -> dict[str, str]:
    must = body["query"]["bool"]["must"]
    return next(clause["range"]["timestamp"] for clause in must if "range" in clause)


def test_search_is_anchored_at_the_alert_not_now() -> None:
    tool, bodies = _tool_and_bodies()
    alert = Alert.model_validate_json((FIXTURES / "ssh_bruteforce_5712.json").read_text())
    tool.run({"srcip": "192.168.64.2", "hours": 24}, alert)
    assert _window(bodies[0])["lte"] == "2026-09-20T00:44:24.533+00:00"


def test_model_cannot_move_the_anchor() -> None:
    tool, bodies = _tool_and_bodies()
    alert = Alert.model_validate_json((FIXTURES / "ssh_bruteforce_5712.json").read_text())
    tool.run({"srcip": "192.168.64.2", "until": "2030-01-01T00:00:00Z"}, alert)
    assert _window(bodies[0])["lte"] == "2026-09-20T00:44:24.533+00:00"


def test_alert_without_timestamp_falls_back_to_now() -> None:
    tool, bodies = _tool_and_bodies()
    alert = Alert.model_validate(
        {"rule": {"id": "1", "level": 3, "description": "x"}, "agent": {"id": "000"}}
    )
    tool.run({}, alert)
    assert _window(bodies[0]) == {"gte": "now-24h"}
