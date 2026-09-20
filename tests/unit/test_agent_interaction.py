import json
import logging
from concurrent.futures import ThreadPoolExecutor

import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.detection.store import EvidenceStore
from gateway.distributed import RedisEvidence


@pytest.fixture(params=["memory", "redis"])
def experiment(request):
    calls = []

    async def origin(request):
        calls.append(request.url.path)
        return httpx.Response(200, text="SECRET-HTML-OR-API")

    shared = fakeredis.FakeRedis(decode_responses=True) if request.param == "redis" else None
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin))
    app = create_app(Settings(dev_access_token="", origin_secret="o" * 32), upstream, shared)
    with TestClient(app) as client:
        yield client, calls


def events(caplog):
    return [json.loads(r.message) for r in caplog.records if r.name == "gateway.events"]


def test_single_trap_replay_sequence_does_not_double_count(experiment, caplog):
    client, calls = experiment
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    assert client.get(challenge["tripwire_url"]).status_code == 204
    assert client.get(challenge["tripwire_url"]).status_code == 410
    assert not calls and "gateway_session" not in client.cookies
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    verification = events(caplog)[-1]
    assert verification["decision"] == "ALLOW"
    assert verification["reason_codes"] == ["tripwire_activation", "trap_before_verification",
                                             "trap_replay", "valid_verified_session"]
    sequence = verification["signals"]["behavior"]["interaction_sequence"]
    assert [e["event"] for e in sequence] == ["challenge_issued", *(["experiment_exposed"] * 3),
                                                "experiment_activated", "experiment_replay",
                                                "verification_submitted", "challenge_consumed", "session_issued"]
    assert [e["order"] for e in sequence] == list(range(1, 10))
    assert all(e["elapsed_ms"] >= 0 for e in sequence)
    assert client.get("/private").text == "SECRET-HTML-OR-API"
    assert client.get("/api/private").text == "SECRET-HTML-OR-API"
    assert calls == ["/private", "/api/private"]
    logged = json.dumps(events(caplog))
    for secret in (challenge["nonce"], challenge["tripwire_url"], client.cookies["gateway_session"],
                   "SECRET-HTML-OR-API"):
        assert secret not in logged


def test_trap_binding_expiry_and_replacement(experiment):
    client, calls = experiment
    first = client.post("/challenge").json()
    second = client.post("/challenge").json()
    assert first["tripwire_url"] != second["tripwire_url"]
    assert client.get(first["tripwire_url"]).status_code == 404
    store = client.app.state.evidence_store
    assert not store.get(first["session_id"]).tripwire_hits
    assert not store.get(second["session_id"]).tripwire_hits
    client.cookies.clear()
    assert client.get(second["tripwire_url"]).status_code == 404
    client.cookies.set("gateway_challenge_session", second["session_id"])
    # Trap lifetime ends even while the 10-minute evidence record remains.
    record = store.get(second["session_id"])
    store.clock = lambda: record.trap_expires_at
    expired = client.get(second["tripwire_url"])
    assert expired.status_code == 404 and expired.content == b""
    assert not store.get(second["session_id"]).tripwire_hits
    assert not calls


def test_post_verification_trap_and_revoked_session(experiment, caplog):
    client, calls = experiment
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    assert "gateway_challenge_session" not in client.cookies
    assert client.get(challenge["tripwire_url"]).status_code == 204
    assert events(caplog)[-1]["signals"]["tripwires"]["activation_phase"] == "after_verification_started"
    assert client.get("/private").status_code == 200
    assert "trap_after_verification_started" in events(caplog)[-1]["reason_codes"]
    calls.clear()
    client.app.state.session_store.revoke(challenge["session_id"], "test-site")
    assert client.get(challenge["tripwire_url"]).status_code == 404
    assert not calls


def test_combined_evidence_and_challenge_replay_never_leak(experiment, caplog):
    client, calls = experiment
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    assert client.get(challenge["tripwire_url"]).content == b""
    response = client.post("/challenge/verify", json={**challenge, "browser": {"webdriver": True}})
    assert response.status_code == 403 and response.content == b""
    denial = events(caplog)[-1]
    assert "multiple_signal_groups" in denial["reason_codes"]
    assert denial["signals"]["behavior"]["interaction_sequence"][-1]["event"] == "verification_denied"
    assert "gateway_session" not in client.cookies
    assert client.post("/challenge/verify", json=challenge).status_code == 403
    for path in ("/private", "/api/private"):
        for accept in ("text/html", "application/json"):
            response = client.get(path, headers={"accept": accept})
            assert "SECRET-HTML-OR-API" not in response.text
    assert not calls


def test_trap_namespace_never_proxies_even_with_valid_session(experiment):
    client, calls = experiment
    challenge = client.post("/challenge").json()
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    for path in (challenge["tripwire_url"], "/challenge/tripwire/unknown",
                 challenge["tripwire_url"] + "/private", "/challenge/tripwire/", "/challenge/tripwire"):
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            response = client.request(method, path)
            assert response.status_code in (204, 404, 405, 410)
            assert response.content == b""
            assert response.headers["cache-control"] == "no-store"
    assert not calls


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_concurrent_trap_consumption_is_atomic_and_sequence_bounded(backend):
    shared = fakeredis.FakeRedis(decode_responses=True)
    store = RedisEvidence(shared, "a") if backend == "redis" else EvidenceStore()
    other = RedisEvidence(shared, "a") if backend == "redis" else store
    record = store.create("session")
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda _: other.activate("session", record.tripwire_id)[0], range(8)))
    assert sorted(outcomes) == [204] + [410] * 7
    for _ in range(70):
        store.activate("session", record.tripwire_id)
    current = other.get("session")
    assert current.tripwire_hits == 1 and current.trap_replays == 77
    snapshot = store.interaction_signals(current)
    assert len(snapshot["behavior"]["interaction_sequence"]) == 64
    assert snapshot["behavior"]["sequence_truncated"]
    assert [e["order"] for e in current.events] == list(range(16, 80))
    if backend == "redis":
        assert RedisEvidence(shared, "other-site").activate("session", record.tripwire_id) == (404, None)
        assert 0 < shared.ttl(store.prefix + "session") <= 600
