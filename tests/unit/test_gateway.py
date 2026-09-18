from datetime import timedelta

import httpx
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.challenges.generator import create_challenge
from gateway.challenges.verifier import verify_challenge
from gateway.config import Settings


class Origin:
    def __init__(self) -> None:
        self.calls = 0

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={"protected": "origin-secret"})


def make_client(origin: Origin) -> TestClient:
    transport = httpx.MockTransport(origin.handle)
    client = httpx.AsyncClient(transport=transport)
    app = create_app(
        Settings(origin_secret="test-origin-secret-at-least-32-characters",
            origin_url="http://origin.test",
            site_id="test-site",
            dev_access_token="test-token",
            token_secret="test-secret",
            timeout_seconds=5,
        ),
        client,
    )
    return TestClient(app)


def test_blocked_request_has_no_origin_content_or_call() -> None:
    origin = Origin()
    with make_client(origin) as client:
        response = client.get("/private")

    assert response.status_code == 403
    assert response.content == b""
    assert "origin-secret" not in response.text
    assert origin.calls == 0


def test_valid_development_token_proxies_to_origin() -> None:
    origin = Origin()
    with make_client(origin) as client:
        response = client.get("/private?view=full", headers={"X-Gateway-Access-Token": "test-token"})

    assert response.status_code == 200
    assert response.json() == {"protected": "origin-secret"}
    assert origin.calls == 1


def test_health_endpoint_does_not_require_access_token() -> None:
    origin = Origin()
    with make_client(origin) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert origin.calls == 0


def test_challenge_lifecycle_rejects_replay_expiry_and_mismatched_sessions() -> None:
    challenge = create_challenge(session_id="session-a")

    assert challenge.challenge_id
    assert challenge.nonce
    assert challenge.status.value == "ISSUED"
    assert challenge.attempt_count == 0

    assert verify_challenge(challenge.challenge_id, "session-a", challenge.nonce) is True
    assert verify_challenge(challenge.challenge_id, "session-a", challenge.nonce) is False
    assert verify_challenge("not-a-real-challenge", "session-a", "nonce") is False
    assert verify_challenge(challenge.challenge_id, "session-b", challenge.nonce) is False

    challenge.expires_at = challenge.created_at - timedelta(seconds=1)
    assert verify_challenge(challenge.challenge_id, "session-a", challenge.nonce) is False

def test_valid_challenge_sets_access_cookie() -> None:
    # Create our fake protected origin.
    origin = Origin()

    with make_client(origin) as client:

        # -------------------------------------------------
        # STEP 1: Ask the gateway to create a challenge.
        # -------------------------------------------------
        challenge_response = client.post(
            "/challenge",
            json={
                "session_id": "browser-123"
            },
        )

        # Challenge creation should succeed.
        assert challenge_response.status_code == 200

        # Convert returned JSON into a Python dictionary.
        challenge = challenge_response.json()

        # -------------------------------------------------
        # STEP 2: Send the challenge back for verification.
        # -------------------------------------------------
        verify_response = client.post(
            "/challenge/verify",
            json={
                "challenge_id": challenge["challenge_id"],
                "session_id": challenge["session_id"],
                "nonce": challenge["nonce"],
            },
        )

        # The correct challenge should be accepted.
        assert verify_response.status_code == 200

        # -------------------------------------------------
        # STEP 3: Check whether the gateway gave us
        # the signed session cookie.
        # -------------------------------------------------

        assert "gateway_session" in client.cookies

        token = client.cookies["gateway_session"]

        # Cookie must actually contain a token.
        assert token

        # -------------------------------------------------
        # IMPORTANT:
        # The challenge endpoints should NOT have contacted
        # the protected origin.
        # -------------------------------------------------
        assert origin.calls == 0
