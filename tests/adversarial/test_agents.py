import runpy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from gateway.sessions.tokens import create_access_token

AGENTS = Path(__file__).resolve().parents[2] / "test-agents"


def agent(name):
    return runpy.run_path(str(AGENTS / name))["probe"]


class HttpxSession(httpx.Client):
    """Run the same HTTP probes with the already-installed HTTPX transport."""

    def get(self, url, *, allow_redirects=False, **kwargs):
        return super().get(url, follow_redirects=allow_redirects, **kwargs)


def test_raw_http_isolation(live_gateway):
    with HttpxSession() as session:
        records = agent("requests_test.py")(session, live_gateway.url)
    assert len(records) == 2
    assert live_gateway.calls == []


def test_requests_library(live_gateway):
    requests = pytest.importorskip("requests", reason="Install .[adversarial] for Requests tests")
    with requests.Session() as session:
        agent("requests_test.py")(session, live_gateway.url)
    assert live_gateway.calls == []


def test_challenge_and_cookie_replay(live_gateway):
    result = agent("replay_test.py")(HttpxSession, live_gateway.url)
    assert result["consumed_challenge_replay"] == "blocked"
    assert result["copied_valid_bearer_cookie"] == "allowed"
    assert live_gateway.calls == ["/private"]


def test_concurrent_captured_verification_only_issues_once(live_gateway):
    with httpx.Client() as client:
        challenge = client.post(live_gateway.url + "/challenge").json()
    cookie = "gateway_challenge_session=" + challenge["session_id"]

    def submit(_):
        with httpx.Client() as client:
            return client.post(live_gateway.url + "/challenge/verify", json=challenge,
                               headers={"Cookie": cookie}).status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(submit, range(4)))
    assert sorted(results) == [200, 403, 403, 403]
    assert live_gateway.calls == []


@pytest.mark.parametrize("variant", ["expired", "wrong-site", "forged", "client-claim",
                                     "legacy-challenge", "development-bypass"])
def test_access_bypass_attempts(live_gateway, variant):
    headers = {}
    if variant == "expired":
        token = create_access_token("attacker", "test-secret", lifetime_seconds=-1)
        headers["Cookie"] = "gateway_session=" + token
    elif variant == "wrong-site":
        token = create_access_token("attacker", "test-secret", site_id="other-site")
        headers["Cookie"] = "gateway_session=" + token
    elif variant == "forged":
        headers["Cookie"] = "gateway_session=forged.signature"
    elif variant == "client-claim":
        headers["Cookie"] = "isHuman=true"
    elif variant == "development-bypass":
        headers["X-Gateway-Access-Token"] = "test-token"
    else:
        with httpx.Client() as client:
            challenge = client.post(live_gateway.url + "/challenge").json()
        headers = {"X-Gateway-Challenge-Id": challenge["challenge_id"],
                   "X-Gateway-Session-Id": challenge["session_id"],
                   "X-Gateway-Challenge-Nonce": challenge["nonce"]}
    with httpx.Client() as client:
        for path in ("/private", "/api/private"):
            response = client.get(live_gateway.url + path, headers=headers)
            assert response.status_code == 403 and response.content == b""
    assert live_gateway.calls == []


def test_chromium_challenge_automation(chromium, live_gateway):
    result = agent("playwright_test.py")(chromium, live_gateway.url, live_gateway.marker)
    assert result["automation_can_complete_challenge"]
    assert live_gateway.calls == ["/private"]


def test_chromium_network_interception(chromium, live_gateway):
    agent("browser_network_test.py")(chromium, live_gateway.url, live_gateway.marker)
    assert live_gateway.calls == ["/private", "/api/private"]


def test_chromium_tripwire_logged_without_single_signal_block(chromium, live_gateway, caplog):
    import json
    import logging

    caplog.set_level(logging.INFO, logger="gateway.events")
    with chromium.new_context() as context:
        page = context.new_page()
        page.goto(live_gateway.url + "/private")
        # Keyboard-only navigation reaches the visible Continue control, not a decoy.
        page.keyboard.press("Tab")
        assert page.get_by_role("button", name="Continue").evaluate("el => el === document.activeElement")
        assert page.locator('[href*="tripwire"]').count() == 0
        challenge = page.evaluate("async () => (await fetch('/challenge', {method: 'POST'})).json()")
        status = page.evaluate("async url => (await fetch(url)).status", challenge["tripwire_url"])
        assert status == 204 and live_gateway.calls == []
        # Submit the protocol directly without optional browser observations.
        status = page.evaluate("""async challenge => (await fetch('/challenge/verify', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(challenge)})).status""", challenge)
        assert status == 200
        page.goto(live_gateway.url + "/private")
        assert live_gateway.marker in page.locator("body").inner_text()
    events = [json.loads(record.message) for record in caplog.records if record.name == "gateway.events"]
    assert any(event["reason_codes"] == ["tripwire_activation"] for event in events)


@pytest.mark.parametrize("path", ["/private", "/api/private"])
def test_direct_origin_bypass_rejected(live_gateway, path):
    with httpx.Client() as client:
        for headers in ({}, {"X-Gateway-Origin-Secret": "forged"},
                        {"X-Forwarded-For": "127.0.0.1", "X-Gateway-Access-Token": "test-token"}):
            denied = client.get(live_gateway.origin_url + path, headers=headers)
            assert denied.status_code == 403 and denied.content == b""
        assert not live_gateway.calls
        challenge = client.post(live_gateway.url + "/challenge").json()
        assert client.post(live_gateway.url + "/challenge/verify", json=challenge).status_code == 200
        allowed = client.get(live_gateway.url + path)
        assert allowed.status_code == 200 and live_gateway.marker in allowed.text
        assert "x-gateway-origin-secret" not in allowed.headers
        # Even possession of a valid gateway session does not authorize the origin.
        direct = client.get(live_gateway.origin_url + path)
        assert direct.status_code == 403 and direct.content == b""
        assert live_gateway.calls == [path]


def test_chromium_cannot_bypass_origin(chromium, live_gateway):
    with chromium.new_context() as context:
        page = context.new_page()
        response = page.goto(live_gateway.origin_url + "/private")
        assert response.status == 403
        assert live_gateway.marker not in page.content()
        api = context.request.get(live_gateway.origin_url + "/api/private")
        assert api.status == 403 and api.body() == b""
        assert live_gateway.calls == []
