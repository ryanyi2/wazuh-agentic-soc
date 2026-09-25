import httpx

from agentic_soc.clients.indexer import IndexerClient


def test_search_alerts_only_hits_the_search_endpoint() -> None:
    recorder: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        recorder["method"] = request.method
        recorder["path"] = request.url.path
        return httpx.Response(
            200,
            json={"hits": {"hits": [{"_source": {"rule": {"id": "5712", "level": 10}}}]}},
        )

    client = IndexerClient("https://x", "u", "p", transport=httpx.MockTransport(handler))
    alerts = client.search_alerts(srcip="1.2.3.4", hours=6)

    assert recorder["method"] == "POST"
    assert recorder["path"].endswith("/_search")  # read-only endpoint, never a write path
    assert alerts[0]["rule"]["id"] == "5712"
