from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.sessions.tokens import create_access_token


@pytest.fixture
def browser():
    calls = []

    async def origin(request):
        calls.append(request)
        return httpx.Response(200, text="protected-origin", headers={"content-type": "text/html"})

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin))
    with TestClient(create_app(Settings(origin_secret="test-origin-secret-at-least-32-characters", ), upstream)) as client:
        yield client, calls


def verify(client):
    challenge = client.post("/challenge", json={"session_id": "attacker-chosen"}).json()
    assert challenge["session_id"] != "attacker-chosen"
    assert client.post("/challenge/verify", json=challenge).status_code == 200
    return challenge


def test_navigation_verification_and_api(browser):
    client, calls = browser
    page = client.get("/private?view=full", headers={"accept": "text/html"})
    assert page.status_code == 200
    assert 'data-next="/private?view=full"' in page.text
    assert "protected-origin" not in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert client.get("/challenge/client.js").status_code == 200
    assert not calls
    challenge = verify(client)
    assert client.get("/private").text == "protected-origin"
    assert client.get("/api/private").status_code == 200
    assert len(calls) == 2
    assert "gateway_" not in calls[0].headers.get("cookie", "")
    assert client.post("/challenge/verify", json=challenge).status_code == 403


@pytest.mark.parametrize("kind", ["modified", "expired", "other-site", "unknown", "revoked"])
def test_invalid_sessions_never_reach_origin(browser, kind):
    client, calls = browser
    challenge = verify(client)
    session = challenge["session_id"]
    token = client.cookies["gateway_session"]
    if kind == "modified":
        token += "x"
    elif kind == "expired":
        token = create_access_token(session, "test-secret", -1)
    elif kind == "other-site":
        token = create_access_token(session, "test-secret", site_id="other")
    elif kind == "unknown":
        token = create_access_token("unknown", "test-secret")
    else:
        client.app.state.session_store.revoke(session, "test-site")
    client.cookies.clear()
    client.cookies.set("gateway_session", token)
    response = client.get("/private")
    assert response.status_code == 403
    assert response.content == b""
    assert not calls


def test_binding_expiration_attempt_limit_and_replay(browser):
    client, calls = browser
    challenge = client.post("/challenge").json()
    cookie = client.cookies["gateway_challenge_session"]
    client.cookies.clear()
    assert client.post("/challenge/verify", json=challenge).status_code == 403
    client.cookies.set("gateway_challenge_session", cookie)
    record = client.app.state.challenge_store.get(challenge["challenge_id"])
    record.expires_at = record.created_at - timedelta(seconds=1)
    assert client.post("/challenge/verify", json=challenge).status_code == 403
    challenge = client.post("/challenge").json()
    assert client.post("/challenge/verify", json={**challenge, "nonce": "wrong"}).status_code == 403
    assert client.post("/challenge/verify", json=challenge).status_code == 403
    challenge = verify(client)
    client.cookies.set("gateway_challenge_session", challenge["session_id"])
    assert client.post("/challenge/verify", json=challenge).status_code == 403
    assert not calls


@pytest.mark.parametrize("target", ["https://evil.test", "//evil.test", "/\\evil.test",
                                    "/%2fevil.test", "/%0a/evil.test", "/challenge"])
def test_navigation_rejects_external_destinations(browser, target):
    client, _ = browser
    response = client.get("/challenge", params={"next": target})
    assert 'data-next="/"' in response.text


def test_invalid_submission_and_unauthorized_methods(browser):
    client, calls = browser
    for body in [[], {}, {"challenge_id": 1, "session_id": True, "nonce": []}]:
        assert client.post("/challenge/verify", json=body).status_code == 422
    assert client.post("/challenge/verify", content="{").status_code == 422
    assert client.get("/api/private").status_code == 403
    assert client.post("/private", headers={"accept": "text/html"}).status_code == 403
    assert not calls
