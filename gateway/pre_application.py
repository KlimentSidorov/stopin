"""Milestone 12 isolated, loopback-only lab. Never installed in the production app."""
import copy
import json
import secrets
import time
from contextlib import asynccontextmanager
from ipaddress import ip_address

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

VARIANTS = ("comment", "inert_manifest", "dormant_function")
VARIANT_RENDERERS = {
    "comment": lambda trap: (f"<!-- Optional application recovery index: {trap} -->", ""),
    "inert_manifest": lambda trap: (
        '<script type="application/json" id="optional-index">' +
        json.dumps({"optional_application_index": trap}) + '</script>', ""),
    "dormant_function": lambda trap: (
        "<!-- Optional diagnostic helper is exported by bootstrap.js -->",
        f'globalThis.stopinOptionalRecovery = () => fetch({json.dumps(trap)});'),
}
COOKIE = "stopin_lab_session"
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
           "Content-Security-Policy": "default-src 'none'; script-src 'self'; "
           "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]


def create_lab(origin: httpx.AsyncClient, *, ttl=90, clock=time.monotonic, variants=None):
    """Caller owns origin client. No origin I/O until an explicit lab grant exists."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    renderers = dict(VARIANT_RENDERERS if variants is None else variants)
    sessions = {}
    events = []
    app.state.sessions = sessions
    app.state.events = events

    def event(kind, run=None, **fields):
        events.append(dict(order=len(events) + 1, at=round(clock(), 6),
                           run=run["number"] if run else None, event=kind, **fields))

    def reply(body="", status=200, media="text/plain"):
        return Response(body, status_code=status, media_type=media, headers=HEADERS)

    @app.middleware("http")
    async def boundary(request, call_next):
        try:
            local = ip_address(request.client.host).is_loopback
        except (ValueError, AttributeError):
            local = False
        if not local or request.url.hostname not in ("127.0.0.1", "localhost", "::1"):
            return reply(status=403)
        return await call_next(request)

    @app.api_route("/{path:path}", methods=METHODS)
    async def dispatch(request: Request, path: str):
        # One worker/event loop; state changes before origin await are atomic.
        # No client reports, browser properties, timings or production tokens used.
        sid = request.cookies.get(COOKIE, "")
        run = sessions.get(sid)
        pieces = path.split("/")
        route = pieces[1] if len(pieces) > 1 and pieces[0] == "__trap" else (
            path if path in ("start", "report", "private", "api/private") else "other")
        event("request", run, method=request.method, route=route)

        def respond(response, protected_bytes=0):
            event("response", run, route=route, status=response.status_code,
                  bytes=len(response.body), protected_bytes=protected_bytes)
            return response

        if path == "report" and request.method == "GET":
            # Local lab observations only; never export challenge/cookie capabilities.
            return respond(JSONResponse({"events": copy.deepcopy(events),
                "runs": [{"number": r["number"], "variant": r["variant"],
                          "tainted": r["tainted"], "granted": r["granted"]}
                         for r in sessions.values()]}, headers=HEADERS))
        if path in ("", "start") and request.method == "GET":
            if len(sessions) >= 500 or len(events) >= 50000:
                return respond(reply(status=503))
            variant = request.query_params.get("variant") or secrets.choice(tuple(renderers))
            if variant not in renderers:
                return respond(reply(status=400))
            sid, capability, optional = (secrets.token_urlsafe(24) for _ in range(3))
            run = dict(number=len(sessions) + 1, variant=variant, expires=clock() + ttl,
                       capability=capability, optional=optional, tainted=False,
                       consumed=False, granted=False)
            sessions[sid] = run
            event("issued", run, variant=variant, lifetime_seconds=ttl)
            trap = f"/__trap/optional/{optional}"
            hint, _ = renderers[variant](trap)
            response = HTMLResponse('<!doctype html><meta charset="utf-8">'
                '<title>Loading</title><link rel="icon" href="data:,">'
                + hint + f'<script src="/__trap/script/{capability}"></script>',
                headers=HEADERS)
            response.set_cookie(COOKIE, sid, httponly=True, samesite="strict", max_age=ttl)
            return respond(response)

        if not run or clock() >= run["expires"]:
            event("denied", run, reason="missing_or_expired_session")
            return respond(reply(status=403))
        if len(pieces) == 3 and pieces[:2] == ["__trap", "optional"]:
            if secrets.compare_digest(pieces[2], run["optional"]):
                run["tainted"] = True
                run["granted"] = False
                event("optional_followed", run, method=request.method)
            return respond(reply(status=403))
        valid = len(pieces) == 3 and secrets.compare_digest(pieces[2], run["capability"])
        if route == "script" and valid and request.method == "GET":
            trap = f"/__trap/optional/{run['optional']}"
            _, optional_js = renderers[run["variant"]](trap)
            script = optional_js + f'''(async () => {{
const r = await fetch('/__trap/complete/{run["capability"]}', {{method: 'POST'}});
if (r.ok) location.replace('/private');
}})();'''
            return respond(reply(script, media="application/javascript"))
        if route == "complete" and valid and request.method == "POST":
            if run["tainted"] or run["consumed"]:
                event("denied", run, reason="exploration_or_replay")
                return respond(reply(status=403))
            run["consumed"] = True
            run["granted"] = True
            event("authorized", run)
            return respond(reply(status=204))
        if path in ("private", "api/private", "_next/data/lab/private.json",
                    "_next/static/lab.js") and request.method == "GET" and run["granted"]:
            event("origin_dispatch", run, route=path)
            upstream = await origin.get('/' + path, follow_redirects=False)
            # Fixture gateway deliberately forwards no browser cookies/credentials,
            # upstream redirects or Set-Cookie; it is not a deployable general proxy.
            return respond(reply(upstream.content, upstream.status_code,
                                 upstream.headers.get("content-type", "text/plain")),
                           protected_bytes=len(upstream.content))
        event("denied", run, reason="not_authorized_or_unknown_route")
        return respond(reply(status=403))

    return app


def create_demo_lab():
    """uvicorn gateway.pre_application:create_demo_lab --factory --host 127.0.0.1"""
    async def fixture(request):
        return httpx.Response(200, text="LAB-PROTECTED-FIXTURE " + request.url.path)

    origin = httpx.AsyncClient(transport=httpx.MockTransport(fixture), base_url="http://fixture")
    app = create_lab(origin)

    @asynccontextmanager
    async def lifespan(_):
        yield
        await origin.aclose()

    app.router.lifespan_context = lifespan
    return app
