import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.origin.protection import OriginProtection

SECRET = "test-origin-secret-at-least-32-characters"


@pytest.mark.parametrize("secret", ["", "short", "x" * 31, "x" * 32 + "\n"])
def test_origin_rejects_unsafe_configuration(secret):
    with pytest.raises(ValueError):
        OriginProtection(FastAPI(), secret)


@pytest.mark.parametrize("path", ["/", "/api/private", "/static/private.txt", "/docs"])
def test_origin_guard_covers_all_routes_and_methods(path):
    calls = []
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST", "HEAD", "OPTIONS"])
    async def private(request: Request):
        calls.append(request)
        return {"protected": True}

    with TestClient(OriginProtection(app, SECRET)) as client:
        for method in ("GET", "POST", "HEAD", "OPTIONS"):
            for headers in ({}, {"X-Gateway-Origin-Secret": "wrong"},
                            {"X-Forwarded-For": "127.0.0.1", "X-Gateway-Access-Token": "test-token"}):
                response = client.request(method, path, headers=headers)
                assert response.status_code == 403 and response.content == b""
        duplicate = client.get(path, headers=[("X-Gateway-Origin-Secret", SECRET),
                                              ("X-Gateway-Origin-Secret", SECRET)])
        assert duplicate.status_code == 403 and not calls
        assert client.get(path, headers={"X-Gateway-Origin-Secret": SECRET}).status_code == 200
        if path != "/docs":
            assert "x-gateway-origin-secret" not in calls[-1].headers


def test_gateway_overwrites_spoofed_header_and_never_follows_redirects():
    calls = []

    async def origin(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://external.test/private",
                                           "x-gateway-origin-secret": SECRET})

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin), follow_redirects=True)
    with TestClient(create_app(Settings(origin_secret=SECRET), upstream)) as client:
        response = client.get("/private", headers={"X-Gateway-Access-Token": "test-token",
            "X-Gateway-Origin-Secret": "attacker", "Connection": "x-gateway-origin-secret"},
            follow_redirects=False)
    assert response.status_code == 302 and len(calls) == 1
    assert calls[0].headers["x-gateway-origin-secret"] == SECRET
    assert "x-gateway-access-token" not in calls[0].headers
    assert "x-gateway-origin-secret" not in response.headers


def test_missing_gateway_origin_secret_fails_closed():
    calls = []

    async def origin(request):
        calls.append(request)
        return httpx.Response(200, text="protected")

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin))
    with TestClient(create_app(Settings(), upstream)) as client:
        response = client.get("/private", headers={"X-Gateway-Access-Token": "test-token"})
    assert response.status_code == 503 and response.content == b"" and not calls
