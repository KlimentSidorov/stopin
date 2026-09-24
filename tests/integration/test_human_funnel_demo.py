import asyncio
import json
import sqlite3

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from gateway.app import create_app as create_gateway
from gateway.config import Settings
from gateway.demo_origin import PROTECTED_MARKER
from gateway.origin.protection import OriginProtection


def test_human_funnel_never_leaks_protected_origin_to_declared_ai(tmp_path):
    async def scenario():
        secret = "demo-origin-secret-0123456789abcdef"
        inner = FastAPI()
        origin_calls = []

        @inner.get("/protected")
        async def protected():
            origin_calls.append("protected")
            return HTMLResponse(PROTECTED_MARKER)

        origin = OriginProtection(inner, secret)

        async def origin_transport(request):
            transport = httpx.ASGITransport(app=origin)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://origin.test"
            ) as client:
                return await client.request(
                    request.method,
                    request.url.path,
                    headers=request.headers,
                    content=request.content,
                )

        policy_db = tmp_path / "dashboard.db"
        with sqlite3.connect(policy_db) as connection:
            connection.executescript(
                """
                CREATE TABLE sites(
                    id TEXT PRIMARY KEY, domain TEXT, origin_url TEXT,
                    policy TEXT, last_seen TEXT
                );
                CREATE TABLE events(
                    request_id TEXT PRIMARY KEY, site_id TEXT, timestamp TEXT,
                    method TEXT, path TEXT, decision TEXT,
                    reason_codes TEXT, signals TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO sites VALUES (?,?,?,?,NULL)",
                (
                    "demo",
                    "gateway.test",
                    "http://origin.test",
                    json.dumps(
                        {
                            "strictness": "balanced",
                            "routes": [{"pattern": "/protected", "action": "human"}],
                        }
                    ),
                ),
            )

        settings = Settings(
            site_id="demo",
            dashboard_db=str(policy_db),
            origin_url="http://origin.test",
            origin_secret=secret,
            dev_access_token="",
        )
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(origin_transport))
        gateway = create_gateway(settings, upstream)
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway),
                base_url="http://gateway.test",
            ) as client:
                blocked = await client.get(
                    "/protected",
                    headers={"accept": "text/html", "user-agent": "GPTBot/1.2"},
                )
                assert blocked.status_code == 403
                assert blocked.content == b""
                assert PROTECTED_MARKER.encode() not in blocked.content
                assert origin_calls == []

                browser = await client.get(
                    "/protected",
                    headers={
                        "accept": "text/html",
                        "user-agent": "Mozilla/5.0 Chrome/153.0.0.0 Safari/537.36",
                    },
                )
                assert browser.status_code == 200
                # Assert protocol/security behavior rather than challenge-page wording.
                assert b'/challenge/client.js' in browser.content
                assert b"JavaScript is required to complete this verification." in browser.content
                assert PROTECTED_MARKER.encode() not in browser.content
                assert origin_calls == []
        finally:
            await upstream.aclose()

    asyncio.run(scenario())
