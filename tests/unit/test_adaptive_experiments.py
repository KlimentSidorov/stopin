import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor

import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.challenges.experiments import FAMILIES, create_experiments
from gateway.config import Settings
from gateway.distributed import RedisEvidence


@pytest.fixture(params=["memory", "redis"])
def adaptive(request):
    calls = []

    async def origin(request):
        calls.append(request.url.path)
        return httpx.Response(200, text="ADAPTIVE-PROTECTED-CONTENT")

    shared = fakeredis.FakeRedis(decode_responses=True) if request.param == "redis" else None
    app = create_app(Settings(dev_access_token="", origin_secret="origin-key-" + "x" * 32),
                     httpx.AsyncClient(transport=httpx.MockTransport(origin)), shared)
    with TestClient(app) as client:
        yield client, calls, shared


def captured(caplog):
    return [json.loads(r.message) for r in caplog.records if r.name == "gateway.events"]


@pytest.mark.parametrize("kind", ["resource", "action", "reference"])
def test_family_binding_expiration_and_secret_isolation(adaptive, kind, caplog):
    client, calls, _ = adaptive
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    descriptor = next(d for d in challenge["experiments"] if d["kind"] == kind)
    cookies = dict(client.cookies)
    for path, accept in (("/private", "text/html"), ("/api/private", "application/json")):
        result = client.get(path, headers={"accept": accept})
        assert "ADAPTIVE-PROTECTED-CONTENT" not in result.text
    # Knowing another session's URL never consumes its experiment or grants access.
    other = client.post("/challenge").json()
    denied = client.request(descriptor["method"], descriptor["url"])
    assert denied.status_code == 404 and denied.content == b""
    client.cookies.clear()
    assert client.request(descriptor["method"], descriptor["url"]).status_code == 404
    client.cookies.update(cookies)
    result = client.request(descriptor["method"], descriptor["url"])
    assert result.status_code == 204 and result.content == b""
    assert result.headers["cache-control"] == "no-store"
    assert "set-cookie" not in result.headers and "gateway_session" not in client.cookies
    assert not client.app.state.session_store.valid(challenge["session_id"], "test-site")
    record = client.app.state.evidence_store.get(challenge["session_id"])
    current = next(e for e in record.experiments if e.descriptor()["kind"] == kind)
    assert current.activated and current.replay_count == 0
    assert all(not e.activated for e in client.app.state.evidence_store.get(other["session_id"]).experiments)
    client.app.state.evidence_store.clock = lambda: current.expires_at
    expired = client.request(descriptor["method"], descriptor["url"])
    assert expired.status_code == 404 and expired.content == b""
    assert not calls
    logged = json.dumps(captured(caplog))
    for secret in (challenge["nonce"], challenge["challenge_id"], descriptor["url"],
                   current.resource_id, current.experiment_id, client.app.state.settings.origin_secret,
                   client.app.state.settings.token_secret, "ADAPTIVE-PROTECTED-CONTENT"):
        assert secret not in logged


@pytest.mark.parametrize("kind", ["resource", "action", "reference"])
def test_accidental_single_family_and_replay_do_not_classify(adaptive, kind, caplog):
    client, calls, _ = adaptive
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    descriptor = next(d for d in challenge["experiments"] if d["kind"] == kind)
    wrong_method = "POST" if descriptor["method"] == "GET" else "GET"
    assert client.request(wrong_method, descriptor["url"]).status_code == 405
    assert client.request(descriptor["method"], descriptor["url"]).status_code == 204
    assert client.request(descriptor["method"], descriptor["url"]).status_code == 410
    assert not calls
    # No browser report: observed activation and replay remain present at verification.
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    event = captured(caplog)[-1]
    assert not event["signals"]["behavior"]["browser_report_supplied"]
    activated = [e for e in event["signals"]["tripwires"]["experiments"] if e["activated"]]
    assert len(activated) == 1 and activated[0]["replays"] == 1
    assert activated[0]["activation_phase"] == "before_verification"
    sequence = event["signals"]["behavior"]["interaction_sequence"]
    assert sequence[activated[0]["activation_order"] - 1]["event"] == "experiment_activated"
    assert event["decision"] == "ALLOW" and "trap_replay" in event["reason_codes"]
    assert client.get("/private").text == "ADAPTIVE-PROTECTED-CONTENT"
    assert client.get("/api/private").text == "ADAPTIVE-PROTECTED-CONTENT"
    logged = json.dumps(captured(caplog))
    assert client.cookies["gateway_session"] not in logged


@pytest.mark.parametrize("browser", [None, {"webdriver": False}, {"webdriver": True}])
def test_server_evidence_survives_omission_or_spoofing(adaptive, browser, caplog):
    client, calls, _ = adaptive
    caplog.set_level(logging.INFO, logger="gateway.events")
    challenge = client.post("/challenge").json()
    for descriptor in challenge["experiments"]:
        assert client.request(descriptor["method"], descriptor["url"]).status_code == 204
    # Keep the existing independent, server-observed burst rule. No new threshold.
    for _ in range(31):
        assert client.get("/api/private").status_code == 403
    body = challenge if browser is None else {**challenge, "browser": browser}
    assert client.post("/challenge/verify", json=body).status_code == 403
    event = captured(caplog)[-1]
    assert "combined_automation_evidence" in event["reason_codes"]
    assert "multiple_experiment_families" in event["reason_codes"]
    assert sum(e["activated"] for e in event["signals"]["tripwires"]["experiments"]) == 3
    assert event["signals"]["behavior"]["browser_report_supplied"] is (browser is not None)
    assert "gateway_session" not in client.cookies and not calls


def test_experiment_namespace_never_proxies_with_authorization(adaptive):
    client, calls, _ = adaptive
    challenge = client.post("/challenge").json()
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    for descriptor in challenge["experiments"]:
        for suffix in ("", "/private"):
            for method in ("GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"):
                response = client.request(method, descriptor["url"] + suffix)
                assert response.status_code in (204, 404, 405, 410)
                assert response.content == b"" and "set-cookie" not in response.headers
    for path in ("/challenge/experiments", "/challenge/experiments/", "/challenge/experiments/unknown"):
        assert client.get(path).status_code == 404
    assert not calls


def test_random_identifiers_binding_and_supported_subsets():
    identifiers = set()
    permutations = set()
    for index in range(32):
        items = create_experiments("challenge-" + str(index), "session-" + str(index), 1, 301)
        permutations.add(tuple(e.experiment_type for e in items))
        for item in items:
            assert item.challenge_id == "challenge-" + str(index)
            assert item.session_id == "session-" + str(index)
            assert item.created_at == 1 and item.expires_at == 301
            for identifier in (item.experiment_id, item.resource_id):
                assert re.fullmatch(r"[A-Za-z0-9_-]{43}", identifier)
                assert identifier not in identifiers
                identifiers.add(identifier)
    # This is a collision/shape check, not a statistical proof of unpredictability.
    assert len(permutations) > 1
    for family in FAMILIES:
        assert len(create_experiments("c", "s", 1, 301, families=(family,))) == 1
    with pytest.raises(ValueError):
        create_experiments("c", "s", 1, 301, families=())


@pytest.mark.parametrize("kind", ["resource", "action", "reference"])
def test_atomic_replay_across_workers_and_sites(adaptive, kind):
    client, _, shared = adaptive
    challenge = client.post("/challenge").json()
    store = client.app.state.evidence_store
    other = RedisEvidence(shared, "test-site") if shared is not None else store
    descriptor = next(d for d in challenge["experiments"] if d["kind"] == kind)
    resource_id = descriptor["url"].rsplit("/", 1)[-1]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: other.activate_experiment(
            challenge["session_id"], resource_id, descriptor["method"])[0], range(8)))
    assert sorted(results) == [204] + [410] * 7
    item = next(e for e in store.get(challenge["session_id"]).experiments if e.resource_id == resource_id)
    assert item.activation_order == 5 and item.replay_count == 7
    other.lifecycle(challenge["session_id"], "verification_submitted")
    sequence = store.get(challenge["session_id"]).events
    assert [e["order"] for e in sequence] == list(range(1, 14))
    if shared is not None:
        assert RedisEvidence(shared, "other-site").activate_experiment(
            challenge["session_id"], resource_id, descriptor["method"]) == (404, None)
        assert 0 < shared.ttl(store.prefix + challenge["session_id"]) <= 600
