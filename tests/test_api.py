import json
from pathlib import Path

from fastapi.testclient import TestClient

from agentic_soc.agent.llm import FakeLLM, LLMResponse
from agentic_soc.api import create_app
from agentic_soc.auth import sign
from agentic_soc.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "test-secret"
VERDICT_JSON = '{"risk_level":"low","confidence":0.5,"summary":"test","root_cause":"test"}'


def _settings() -> Settings:
    # _env_file=None: tests must never read the real .env, so they can never
    # write verdicts into the log that Wazuh ingests.
    return Settings(_env_file=None, hmac_secret=SECRET, min_rule_level=9)


def _client(llm: FakeLLM | None = None) -> TestClient:
    llm = llm or FakeLLM(responses=[LLMResponse(text=VERDICT_JSON)])
    return TestClient(create_app(_settings(), llm=llm, tools={}))


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


def test_own_verdict_alerts_are_never_reanalysed() -> None:
    alert = json.loads(_body("ssh_bruteforce_5712.json"))
    alert["rule"]["groups"].append("agentic_soc")
    body = json.dumps(alert).encode()
    sig = sign(body, SECRET)
    llm = FakeLLM(responses=[LLMResponse(text=VERDICT_JSON)])
    with _client(llm) as client:
        resp = client.post("/v1/alerts", content=body, headers={"X-Signature": sig})
    assert resp.status_code == 202
    assert resp.json() == {"status": "ignored"}
    assert llm.calls == 0  # the agent never saw it
