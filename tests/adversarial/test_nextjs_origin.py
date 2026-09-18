import httpx
import pytest

MARKER = "NEXTJS-PROTECTED-ORIGIN-CONTENT"


def verify(client, url):
    challenge = client.post(url + "/challenge").json()
    assert client.post(url + "/challenge/verify", json=challenge).status_code == 200


@pytest.mark.parametrize("path", ["/private", "/api/private", "/private.txt"])
def test_nextjs_direct_access_denied_gateway_allowed(nextjs_gateway, path):
    gateway = nextjs_gateway
    with httpx.Client() as client:
        for method in ("GET", "POST", "HEAD", "OPTIONS"):
            for headers in ({}, {"X-Gateway-Origin-Secret": "forged"},
                            {"X-Forwarded-For": "127.0.0.1", "X-Middleware-Subrequest": "middleware"}):
                response = client.request(method, gateway.origin.url + path, headers=headers)
                assert response.status_code == 403 and response.content == b""
        assert client.get(gateway.url + path).status_code == 403
        verify(client, gateway.url)
        allowed = client.get(gateway.url + path, headers={"X-Gateway-Origin-Secret": "spoofed"})
        assert allowed.status_code == 200 and MARKER in allowed.text
        assert gateway.origin.secret not in allowed.text
        assert "x-gateway-origin-secret" not in allowed.headers
        if path == "/api/private":
            assert allowed.json()["originSecretVisible"] is False
        # Cookie reuse at the origin cannot bypass its independent credential check.
        assert client.get(gateway.origin.url + path).status_code == 403


def test_nextjs_duplicate_secret_denied(nextjs_origin):
    with httpx.Client() as client:
        response = client.get(nextjs_origin.url + "/private", headers=[
            ("X-Gateway-Origin-Secret", nextjs_origin.secret),
            ("X-Gateway-Origin-Secret", nextjs_origin.secret)])
        assert response.status_code == 403 and response.content == b""


def test_nextjs_chromium_navigation_and_assets(chromium, nextjs_gateway):
    gateway = nextjs_gateway
    with chromium.new_context() as context:
        page = context.new_page()
        assert page.goto(gateway.origin.url + "/private").status == 403
        page.goto(gateway.url + "/private")
        assert MARKER not in page.content()
        page.get_by_role("button", name="Continue", exact=True).click()
        page.locator("#verification").wait_for(state="detached")
        assert MARKER in page.locator("body").inner_text()
        assets = page.locator('script[src]').evaluate_all("els => els.map(el => el.getAttribute('src'))")
        assert assets
        for asset in assets:
            assert asset.startswith("/_next/")
            allowed = context.request.get(gateway.url + asset)
            assert allowed.status == 200
            assert gateway.origin.secret not in allowed.text()
            denied = context.request.get(gateway.origin.url + asset)
            assert denied.status == 403 and denied.body() == b""
        api = context.request.get(gateway.url + "/api/private")
        assert api.status == 200 and api.json()["originSecretVisible"] is False
        assert context.request.get(gateway.origin.url + "/api/private").status == 403
