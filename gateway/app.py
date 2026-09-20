import logging
import secrets
import sqlite3
from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from redis import Redis
from redis.exceptions import RedisError
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.concurrency import run_in_threadpool

from gateway.challenges.generator import create_challenge
from gateway.challenges.page import CLIENT_SCRIPT, challenge_page
from gateway.challenges.store import InMemoryChallengeStore
from gateway.challenges.verifier import verify_challenge
from gateway.config import Settings
from gateway.dashboard import DashboardStore, evaluate_dashboard
from gateway.detection.engine import collect_signals
from gateway.detection.signals import BrowserReport
from gateway.detection.store import EvidenceStore
from gateway.distributed import RedisChallenges, RedisSessions, RedisEvidence
from gateway.hardening import BoundaryMiddleware, RequestControls
from gateway.logging.events import record_decision
from gateway.origin.protection import validate_secret
from gateway.policies.evaluator import Decision
from gateway.proxy.origin_proxy import proxy_request
from gateway.sessions.store import InMemorySessionStore
from gateway.sessions.tokens import create_access_token, verify_access_token

logging.basicConfig(level=logging.INFO)
LIFETIME = 300
PRIVATE_HEADERS = {"Cache-Control": "no-store", "Vary": "Accept, Cookie",
                   "X-Content-Type-Options": "nosniff"}


class ChallengeSubmission(BaseModel):
    model_config = ConfigDict(strict=True)
    challenge_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    nonce: str = Field(min_length=1, max_length=128)
    browser: BrowserReport | None = None


def create_app(settings: Settings | None = None,
               client: httpx.AsyncClient | None = None, redis_client=None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate()
    shared = redis_client if redis_client is not None else (
        Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2,
                       socket_connect_timeout=2, max_connections=50) if settings.redis_url else None)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if shared is not None:
            await run_in_threadpool(shared.ping)
        if settings.production:
            await run_in_threadpool(configuration)
        if app.state.client is None:
            app.state.client = httpx.AsyncClient(timeout=settings.timeout_seconds)
        yield
        if client is None:
            await app.state.client.aclose()
        if shared is not None and redis_client is None:
            await run_in_threadpool(shared.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.client = client
    app.state.challenge_store = RedisChallenges(shared, settings.site_id) if shared is not None else InMemoryChallengeStore()
    app.state.session_store = RedisSessions(shared, settings.site_id) if shared is not None else InMemorySessionStore()
    app.state.evidence_store = RedisEvidence(shared, settings.site_id) if shared is not None else EvidenceStore()
    controls = RequestControls(settings, shared)
    app.state.controls = controls
    app.add_middleware(BoundaryMiddleware, controls=controls)
    if settings.allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    dashboard = DashboardStore(settings.dashboard_db) if settings.dashboard_db else None

    def record_event(**event):
        record_decision(**event)
        if dashboard:
            dashboard.record(**event)

    def configuration():
        if dashboard:
            return dashboard.configuration(settings)
        return settings, {"strictness": "balanced", "routes": []}

    def cookie(response: Response, name: str, value: str) -> None:
        response.set_cookie(name, value, httponly=True, secure=settings.cookie_secure,
                            samesite="strict", max_age=LIFETIME, path="/")

    def page(destination: str) -> Response:
        headers = {**PRIVATE_HEADERS, "Content-Security-Policy":
                   "default-src 'none'; script-src 'self'; connect-src 'self'; "
                   "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}
        return HTMLResponse(challenge_page(destination), headers=headers)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        try:
            if shared is not None:
                shared.ping()
            configuration()
        except (RedisError, ValueError, OSError, sqlite3.Error):
            return Response(status_code=503, headers=PRIVATE_HEADERS)
        return JSONResponse({"status": "ready"}, headers=PRIVATE_HEADERS)

    @app.get("/metrics")
    def metrics(request: Request):
        expected = 'Bearer ' + settings.metrics_token
        if not settings.metrics_token or not secrets.compare_digest(
                request.headers.get('authorization', '').encode(), expected.encode()):
            return Response(status_code=403, headers=PRIVATE_HEADERS)
        return Response(controls.metrics(), media_type='text/plain; version=0.0.4', headers=PRIVATE_HEADERS)

    @app.get("/challenge")
    async def show_challenge(request: Request):
        return page(request.query_params.get("next", "/"))

    @app.get("/challenge/client.js")
    async def challenge_script():
        return Response(CLIENT_SCRIPT, media_type="application/javascript", headers=PRIVATE_HEADERS)

    @app.post("/challenge")
    def issue_challenge():
        # Identity is generated by the server, never selected by the request body.
        session_id = secrets.token_urlsafe(32)
        challenge = create_challenge(session_id=session_id, store=app.state.challenge_store)
        evidence = app.state.evidence_store.create(session_id)
        payload = challenge.to_dict()
        payload["tripwire_url"] = "/challenge/tripwire/" + evidence.tripwire_id
        descriptors, interaction = app.state.evidence_store.expose_experiments(session_id, challenge.challenge_id)
        payload["experiments"] = descriptors
        record_event(request_id=str(uuid4()), site_id=settings.site_id, method="POST",
                     path="/challenge", decision="OBSERVE", reasons=["experiment_exposed"],
                     session_id=session_id, signals=interaction)
        response = JSONResponse(payload, headers=PRIVATE_HEADERS)
        cookie(response, "gateway_challenge_session", session_id)
        return response

    @app.api_route("/challenge/tripwire",
                   methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    @app.api_route("/challenge/tripwire/{tripwire_id:path}",
                   methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    def tripwire(request: Request, tripwire_id: str = ""):
        # Reserve the whole namespace, including malformed paths and methods.
        # None of these requests may fall through to the protected origin.
        if request.method != "GET":
            return Response(status_code=405, headers={**PRIVATE_HEADERS, "Allow": "GET"})
        session_id = interaction_session(request)
        status, interaction = app.state.evidence_store.activate(session_id, tripwire_id)
        if interaction:
            record_event(request_id=str(uuid4()), site_id=settings.site_id, method="GET",
                        path="/challenge/tripwire", decision="OBSERVE",
                        reasons=["tripwire_activation" if status == 204 else "trap_replay"],
                        session_id=session_id, signals=interaction)
        return Response(status_code=status, headers=PRIVATE_HEADERS)

    def interaction_session(request):
        session_id = request.cookies.get("gateway_challenge_session")
        token = request.cookies.get("gateway_session")
        if not session_id and token:
            candidate = verify_access_token(token, settings.token_secret, settings.site_id,
                                            settings.token_previous_secrets)
            if candidate and app.state.session_store.valid(candidate, settings.site_id):
                session_id = candidate
        return session_id

    @app.api_route("/challenge/experiments",
                   methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    @app.api_route("/challenge/experiments/{resource_id:path}",
                   methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    def experiment_resource(request: Request, resource_id: str = ""):
        session_id = interaction_session(request)
        status, interaction = app.state.evidence_store.activate_experiment(
            session_id, resource_id, request.method)
        if interaction:
            record_event(request_id=str(uuid4()), site_id=settings.site_id, method=request.method,
                         path="/challenge/experiments", decision="OBSERVE",
                         reasons=["experiment_activation" if status == 204 else "experiment_replay"],
                         session_id=session_id, signals=interaction)
        return Response(status_code=status, headers=PRIVATE_HEADERS)

    @app.post("/challenge/verify")
    def verify_challenge_endpoint(request: Request, body: ChallengeSubmission):
        bound_session = request.cookies.get("gateway_challenge_session", "")
        if secrets.compare_digest(bound_session.encode(), body.session_id.encode()):
            app.state.evidence_store.lifecycle(bound_session, "verification_submitted")
        if (not secrets.compare_digest(bound_session.encode(), body.session_id.encode())
                or not verify_challenge(body.challenge_id, bound_session, body.nonce,
                                        store=app.state.challenge_store)):
            app.state.evidence_store.failure(bound_session)
            interaction = app.state.evidence_store.lifecycle(bound_session, "verification_rejected")
            record_event(request_id=str(uuid4()), site_id=settings.site_id,
                            method="POST", path="/challenge/verify", decision="BLOCK",
                            reasons=["invalid_challenge"], signals=interaction)
            return Response(status_code=403, headers=PRIVATE_HEADERS)
        app.state.evidence_store.report(bound_session, body.browser.model_dump() if body.browser else None)
        app.state.evidence_store.lifecycle(bound_session, "challenge_consumed")
        signals = collect_signals(request, settings, app.state.session_store, app.state.evidence_store)
        # A consumed, valid challenge establishes eligibility; client claims do not.
        signals.session.update(valid=True, invalid_token=False, development=False, id=bound_session)
        try:
            _, policy = configuration()
        except (ValueError, OSError, sqlite3.Error):
            return Response(status_code=503, headers=PRIVATE_HEADERS)
        # Route rules apply to the protected destination, not the internal verifier.
        decision, reasons = evaluate_dashboard(signals, {**policy, "routes": []}, request.url.path)
        if decision is Decision.ALLOW:
            app.state.session_store.issue(bound_session, settings.site_id, LIFETIME)
        interaction = app.state.evidence_store.lifecycle(
            bound_session, "session_issued" if decision is Decision.ALLOW else "verification_denied")
        if interaction:
            signals.behavior.update(interaction["behavior"])
        record_event(request_id=str(uuid4()), site_id=settings.site_id,
                        method="POST", path="/challenge/verify", decision=decision.value,
                        reasons=reasons, session_id=bound_session, signals=signals.to_dict())
        if decision is not Decision.ALLOW:
            return Response(status_code=403, headers=PRIVATE_HEADERS)
        token = create_access_token(bound_session, settings.token_secret, LIFETIME, settings.site_id)
        response = Response(content=b"challenge-valid", headers=PRIVATE_HEADERS)
        cookie(response, "gateway_session", token)
        response.delete_cookie("gateway_challenge_session", path="/",
                               secure=settings.cookie_secure, httponly=True, samesite="strict")
        return response

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE",
                                           "OPTIONS", "HEAD"])
    async def gateway(request: Request):
        request_id = str(uuid4())
        try:
            active_settings, policy = await run_in_threadpool(configuration)
        except (ValueError, OSError, sqlite3.Error):
            await run_in_threadpool(record_event, request_id=request_id, site_id=settings.site_id, method=request.method,
                         path=request.url.path, decision="BLOCK", reasons=["dashboard_configuration_unavailable"])
            return Response(status_code=503, headers={**PRIVATE_HEADERS, "x-request-id": request_id})
        signals = await run_in_threadpool(collect_signals, request, settings,
                                          app.state.session_store, app.state.evidence_store)
        decision, reasons = evaluate_dashboard(signals, policy, request.url.path)
        await run_in_threadpool(record_event, request_id=request_id, site_id=settings.site_id,
                        method=request.method, path=request.url.path,
                        decision=decision.value, reasons=reasons,
                        session_id=signals.session.get("id"), signals=signals.to_dict())
        if decision is Decision.CHALLENGE:
            destination = request.url.path
            if request.url.query:
                destination += "?" + request.url.query
            response = page(destination)
        elif decision is Decision.BLOCK:
            response = Response(status_code=403, headers=PRIVATE_HEADERS)
        else:
            try:
                validate_secret(settings.origin_secret)
            except ValueError:
                return Response(status_code=503, headers={**PRIVATE_HEADERS,
                                                         "x-request-id": request_id})
            try:
                origin = await proxy_request(app.state.client, request, active_settings.origin_url,
                                             settings.origin_secret)
            except httpx.RequestError:
                return Response(status_code=502, headers={**PRIVATE_HEADERS,
                                                         "x-request-id": request_id})
            excluded = {"content-length", "transfer-encoding", "connection", "content-encoding",
                        "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
                        "trailer", "upgrade", "set-cookie"}
            excluded.update(part.strip().lower() for part in origin.headers.get("connection", "").split(","))
            headers = {key: value for key, value in origin.headers.items() if key.lower() not in excluded
                       and not key.lower().startswith("x-gateway-")}
            headers.update({"cache-control": "no-store", "vary": "Accept, Cookie"})
            response = Response(origin.content, status_code=origin.status_code, headers=headers)
            for value in origin.headers.get_list("set-cookie"):
                if not value.split("=", 1)[0].strip().lower().startswith("gateway_"):
                    response.headers.append("set-cookie", value)
        response.headers["x-request-id"] = request_id
        return response

    return app


app = create_app()
