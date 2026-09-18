import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.detection.signals import Signals
from gateway.detection.store import EvidenceStore
from gateway.policies.evaluator import Decision, evaluate_signals


@pytest.fixture
def gateway():
    calls = []

    async def origin(request):
        calls.append(request)
        return httpx.Response(200, text="protected-data")

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin))
    with TestClient(create_app(Settings(origin_secret="test-origin-secret-at-least-32-characters", dev_access_token=""), upstream)) as client:
        yield client, calls


@pytest.mark.parametrize("group,value", [
    ("tripwires", {"activated": True}), ("rate", {"burst": True}),
    ("browser", {"webdriver": True}), ("request", {"header_inconsistent": True})])
def test_single_signal_never_blocks_verified_session(group, value):
    signals = Signals(session={"valid": True})
    setattr(signals, group, value)
    assert evaluate_signals(signals)[0] is Decision.ALLOW


def test_combined_signals_and_invalid_credentials():
    signals = Signals(session={"valid": True}, request={"html_navigation": True},
                      browser={"webdriver": True}, rate={"burst": True})
    assert evaluate_signals(signals)[0] is Decision.CHALLENGE
    signals.tripwires = {"activated": True}
    assert evaluate_signals(signals)[0] is Decision.BLOCK
    signals.session = {"invalid_token": True, "development": True}
    assert evaluate_signals(signals) == (Decision.BLOCK, ["invalid_session"])


def test_tripwire_binding_false_positive_and_combined_block(gateway, caplog):
    client, calls = gateway
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    tripwire = challenge["tripwire_url"]
    cookie = client.cookies.get("gateway_challenge_session")
    client.cookies.clear()
    assert client.get(tripwire).status_code == 404
    client.cookies.set("gateway_challenge_session", cookie)
    assert client.get(tripwire).status_code == 204
    assert client.get("/challenge/tripwire/unknown").status_code == 404
    assert not calls
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    assert client.get("/private").status_code == 200  # A single hit never blocks.
    evidence = client.app.state.evidence_store.get(challenge["session_id"])
    for _ in range(30):
        client.app.state.evidence_store.observe(evidence, "page")
    calls.clear()
    response = client.get("/private", headers={"accept": "text/html"})
    assert response.status_code == 403 and not calls
    events = [json.loads(record.message) for record in caplog.records if record.name == "gateway.events"]
    assert any(event["reason_codes"] == ["tripwire_activation"] for event in events)
    assert "combined_automation_evidence" in events[-1]["reason_codes"]
    assert set(events[-1]["signals"]) == {"request", "browser", "behavior", "tripwires", "rate", "crawler", "session"}
    logged = json.dumps(events)
    assert challenge["nonce"] not in logged
    assert client.cookies.get("gateway_session") not in logged
    assert "protected-data" not in logged


def test_browser_report_is_optional_and_cannot_grant_access(gateway):
    client, calls = gateway
    assert client.post("/challenge/verify", json={"isHuman": True}).status_code == 422
    challenge = client.post("/challenge").json()
    report = {"javascript": True, "webdriver": True, "elapsed_ms": 100.0}
    assert client.post("/challenge/verify", json={**challenge, "browser": report}).status_code == 200
    assert client.get("/private").status_code == 200
    record = client.app.state.evidence_store.get(challenge["session_id"])
    assert record.browser == report and record.verification_ms is not None
    calls.clear()
    for _ in range(30):
        client.app.state.evidence_store.observe(record, "page")
    response = client.get("/private", headers={"accept": "text/html"})
    assert "Verify access" in response.text and not calls


def test_combined_evidence_denies_session_issuance(gateway):
    client, calls = gateway
    challenge = client.post("/challenge").json()
    assert client.get(challenge["tripwire_url"]).status_code == 204
    result = client.post("/challenge/verify", json={**challenge, "browser": {
        "javascript": True, "webdriver": True, "elapsed_ms": 1.0}})
    assert result.status_code == 403
    assert "gateway_session" not in client.cookies and not calls


def test_evidence_expiration_capacity_and_rate_window():
    now = [0]
    store = EvidenceStore(ttl=60, capacity=2, clock=lambda: now[0])
    first = store.create("first")
    store.create("second")
    store.create("third")
    assert store.get("first") is None and len(store.records) == 2
    for _ in range(200):
        store.observe(first, "api")
    assert len(first.requests) == 101
    now[0] = 11
    assert store.observe(first, "page") == (1, "api")
    now[0] = 61
    assert store.get("second") is None


@pytest.mark.parametrize("browser", [{"webdriver": "true"}, {"elapsed_ms": -1}, {"isHuman": True}])
def test_browser_schema_rejects_invalid_claims(gateway, browser):
    client, _ = gateway
    challenge = client.post("/challenge").json()
    assert client.post("/challenge/verify", json={**challenge, "browser": browser}).status_code == 422
