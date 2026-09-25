import json
from datetime import UTC, datetime
from typing import Any

import httpx

from agentic_soc.clients.indexer import IndexerClient


def _client(recorder: dict[str, Any]) -> IndexerClient:
    def handler(request: httpx.Request) -> httpx.Response:
        recorder["method"] = request.method
        recorder["path"] = request.url.path
        recorder["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"hits": {"hits": [{"_source": {"rule": {"id": "5712", "level": 10}}}]}},
        )

    return IndexerClient("https://x", "u", "p", transport=httpx.MockTransport(handler))


def _time_range(body: dict[str, Any]) -> dict[str, str]:
    must = body["query"]["bool"]["must"]
    return next(clause["range"]["timestamp"] for clause in must if "range" in clause)


def test_search_alerts_only_hits_the_search_endpoint() -> None:
    recorder: dict[str, Any] = {}
    alerts = _client(recorder).search_alerts(srcip="1.2.3.4", hours=6)

    assert recorder["method"] == "POST"
    assert recorder["path"].endswith("/_search")  # read-only endpoint, never a write path
    assert alerts[0]["rule"]["id"] == "5712"


def test_search_without_anchor_looks_back_from_now() -> None:
    recorder: dict[str, Any] = {}
    _client(recorder).search_alerts(hours=6)
    assert _time_range(recorder["body"]) == {"gte": "now-6h"}


def test_search_with_anchor_never_sees_later_events() -> None:
    recorder: dict[str, Any] = {}
    fired = datetime(2026, 9, 20, 0, 44, 24, 533000, tzinfo=UTC)
    _client(recorder).search_alerts(hours=6, until=fired)
    window = _time_range(recorder["body"])
    assert window["gte"] == "2026-09-19T18:44:24.533+00:00"
    assert window["lte"] == "2026-09-20T00:44:24.533+00:00"  # ends when the alert fired
