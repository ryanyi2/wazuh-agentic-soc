from pathlib import Path

from fastapi.testclient import TestClient

from agentic_soc.api import create_app
from agentic_soc.auth import sign
from agentic_soc.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "test-secret"


def _client() -> TestClient:
    return TestClient(create_app(Settings(hmac_secret=SECRET, min_rule_level=9)))


def _body(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_health() -> None:
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_valid_alert_accepted() -> None:
    body = _body("ssh_bruteforce_5712.json")
    sig = sign(body, SECRET)
    with _client() as client:
        resp = client.post("/v1/alerts", content=body, headers={"X-Signature": sig})
    assert resp.status_code == 202
    assert resp.json() == {"status": "accepted"}


def test_bad_signature_rejected() -> None:
    body = _body("ssh_bruteforce_5712.json")
    with _client() as client:
        resp = client.post("/v1/alerts", content=body, headers={"X-Signature": "deadbeef"})
    assert resp.status_code == 401


def test_malformed_body_rejected() -> None:
    body = b'{"not":"an alert"}'
    sig = sign(body, SECRET)
    with _client() as client:
        resp = client.post("/v1/alerts", content=body, headers={"X-Signature": sig})
    assert resp.status_code == 422
