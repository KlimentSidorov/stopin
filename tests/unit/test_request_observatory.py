from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from gateway.request_observatory import observe_request, summarize_observations


def make_client(captured):
    app = FastAPI()

    @app.get("/probe")
    async def probe(request: Request):
        captured.append(observe_request(request, route="start"))
        return {"ok": True}

    return TestClient(app)


def test_observatory_keeps_useful_http_metadata_but_drops_secrets_and_proxy_metadata():
    captured = []
    with make_client(captured) as client:
        response = client.get("/probe?secret=query-value", headers={
            "User-Agent": "example-agent/1.0",
            "Accept": "text/html",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Mode": "navigate",
            "Authorization": "Bearer do-not-export",
            "Cookie": "session=do-not-export",
            "X-Forwarded-For": "203.0.113.10",
            "True-Client-IP": "198.51.100.20",
            "CF-Ray": "provider-trace",
            "X-Custom-Trace": "safe-name-only",
        })
    assert response.status_code == 200
    observation = captured[0]
    assert observation["route"] == "start"
    assert observation["method"] == "GET"
    assert observation["headers"]["user-agent"] == "example-agent/1.0"
    assert observation["headers"]["accept"] == "text/html"
    assert observation["headers"]["sec-fetch-mode"] == "navigate"
    assert observation["has_cookie"] is True
    assert observation["has_authorization"] is True
    assert "accept" in observation["header_names"]
    assert "sec-fetch-mode" in observation["header_names"]
    for excluded in (
        "authorization", "cookie", "x-forwarded-for", "true-client-ip",
        "cf-ray", "x-custom-trace", "host",
    ):
        assert excluded not in observation["header_names"]
    exported = repr(observation)
    for secret in (
        "do-not-export", "203.0.113.10", "198.51.100.20", "provider-trace",
        "query-value", "safe-name-only",
    ):
        assert secret not in exported


def test_observatory_summarizes_request_progression_without_identity_claims():
    observations = [
        {"route": "start", "has_cookie": False},
        {"route": "script", "has_cookie": True},
        {"route": "complete", "has_cookie": True},
        {"route": "protected", "has_cookie": True},
    ]
    summary = summarize_observations(observations)
    assert summary == {
        "request_count": 4,
        "routes": ["start", "script", "complete", "protected"],
        "script_requested": True,
        "completion_requested": True,
        "optional_requested": False,
        "protected_requested": True,
        "cookie_seen_after_entry": True,
    }
