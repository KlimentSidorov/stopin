"""Hosted research evaluator with a sanitized HTTP request observatory.

This wraps the Milestone 13 app without changing its authorization decisions. The
observatory is evaluator-authenticated and records only allowlisted HTTP metadata.
"""
import copy
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from gateway.hosted_agent_evaluation import HEADERS, create_app as create_evaluator
from gateway.request_observatory import observe_request, summarize_observations


def create_app(*, evaluator_token=None, public_base_url=None, cookie_secure=None):
    token = evaluator_token if evaluator_token is not None else os.getenv(
        "STOPIN_EVALUATOR_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("STOPIN_EVALUATOR_TOKEN must contain at least 32 characters")

    evaluator = create_evaluator(evaluator_token=token,
                                 public_base_url=public_base_url,
                                 cookie_secure=cookie_secure)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    observations = {}
    app.state.evaluator = evaluator
    app.state.observations = observations

    def control_authorized(request):
        supplied = request.headers.get("authorization", "")
        expected = "Bearer " + token
        return secrets.compare_digest(supplied.encode(), expected.encode())

    def run_for_request(request):
        path = request.url.path
        if path.startswith("/evaluate/"):
            entry = path.rsplit("/", 1)[-1]
            for run in evaluator.state.runs.values():
                if secrets.compare_digest(run.get("entry", ""), entry):
                    return run
            return None
        sid = request.cookies.get("stopin_hosted_evaluation", "")
        if not sid:
            return None
        for run in evaluator.state.runs.values():
            candidate = run.get("session") or ""
            if candidate and secrets.compare_digest(candidate, sid):
                return run
        return None

    def route_name(request):
        path = request.url.path
        if path.startswith("/evaluate/"):
            return "start"
        pieces = path.split("/")
        if len(pieces) == 4 and pieces[1] == "__evaluation":
            return pieces[2] if pieces[2] in {
                "script", "optional", "complete", "protected"} else "other"
        return "other"

    @app.middleware("http")
    async def collect(request, call_next):
        # Never observe the authenticated evaluator control plane.
        if not request.url.path.startswith("/__evaluator/"):
            run = run_for_request(request)
            if run is not None:
                item = observe_request(request, route=route_name(request))
                observations.setdefault(run["run_id"], []).append(item)
        response = await call_next(request)
        for key, value in HEADERS.items():
            response.headers[key] = value
        return response

    @app.get("/__observatory/runs/{run_id}")
    async def get_observations(request: Request, run_id: str):
        if not control_authorized(request):
            return Response(status_code=403, headers=HEADERS)
        run = evaluator.state.runs.get(run_id)
        if run is None:
            return Response(status_code=404, headers=HEADERS)
        items = copy.deepcopy(observations.get(run_id, []))
        return JSONResponse({
            "schema_version": 1,
            "run_id": run_id,
            "agent_label": run["agent_label"],
            "bootstrap_variant": run["variant"],
            "observations": items,
            "summary": summarize_observations(items),
            "interpretation": (
                "Server-observed HTTP behavior only. These observations do not prove "
                "AI, automation, humanity, provider identity, or malicious intent."
            ),
        }, headers=HEADERS)

    # Delegate every non-observatory route to the existing evaluator. This preserves
    # the tested single-use URL, synthetic origin, trap and finalization semantics.
    app.mount("/", evaluator)
    return app
