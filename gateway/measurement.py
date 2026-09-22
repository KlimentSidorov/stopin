"""Opt-in, worker-local research observations. Never an authorization input."""
import copy
import secrets
import time
import statistics
from datetime import datetime, timezone
from collections import OrderedDict
from contextvars import ContextVar
from ipaddress import ip_address
from threading import RLock

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

CURRENT = ContextVar("measurement_request", default=None)
PREFIX = "/__measurement"
COOKIE = "gateway_measurement"
COHORTS = ("manual_chrome", "manual_firefox", "manual_mobile", "normal_visible_flow",
           "resource_explorer", "protocol_explorer", "telemetry_omitting_explorer",
           "stopin_aware_adversary")
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
           "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"}


def local(request):
    try:
        return (ip_address(request.client.host).is_loopback and
                request.url.hostname in ("127.0.0.1", "localhost", "::1"))
    except (ValueError, AttributeError):
        return False


class Measurements:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.runs = OrderedDict()
        self.lock = RLock()

    def start(self, cohort):
        with self.lock:
            while len(self.runs) >= 200:
                self.runs.popitem(last=False)
            key = secrets.token_urlsafe(32)
            self.runs[key] = dict(start=self.clock(), cohort=cohort, completed=False,
                                  label=None, events=[], requests=0, truncated=False,
                                  sessions={}, seen={})
            return key

    def get(self, key):
        run = self.runs.get(key)
        if run and self.clock() - run["start"] < 7200:
            return run
        self.runs.pop(key, None)

    def event(self, kind, **values):
        context = CURRENT.get()
        if not context:
            return
        key, request_number = context
        with self.lock:
            run = self.get(key)
            if not run or run["completed"]:
                return
            if len(run["events"]) >= 2000:
                run["truncated"] = True
                return
            run["events"].append(dict(order=len(run["events"]) + 1,
                request=request_number, event=kind,
                elapsed_ms=round((self.clock() - run["start"]) * 1000, 3), **values))

    def evidence(self, event):
        """Allowlist existing server evidence; never serialize signals wholesale."""
        context = CURRENT.get()
        if not context:
            return
        with self.lock:
            run = self.get(context[0])
            if not run or run["completed"]:
                return
            sid = event.get("session_id")
            signals = event.get("signals") or {}
            behavior = signals.get("behavior", {})
            if sid:
                number = run["sessions"].setdefault(sid, len(run["sessions"]) + 1)
                last = run["seen"].get(sid, 0)
                for item in behavior.get("interaction_sequence", []):
                    if item["order"] > last:
                        self.event(item["event"], session=number,
                                   challenge_elapsed_ms=item["elapsed_ms"],
                                   family=item.get("family"))
                        last = item["order"]
                run["seen"][sid] = last
            if event["decision"] != "OBSERVE":
                self.event("access_decision", decision=event["decision"],
                           session_valid=bool(signals.get("session", {}).get("valid")),
                           session_continuity=bool(signals.get("session", {}).get("continuity")))

    def export(self):
        with self.lock:
            rows = []
            for key in list(self.runs):
                run = self.get(key)
                if run:
                    rows.append(dict(cohort=run["cohort"], completed=run["completed"],
                        label=run["label"], SERVER_OBSERVED=dict(events=copy.deepcopy(run["events"]),
                        request_count=run["requests"], truncated=run["truncated"]),
                        CLIENT_REPORTED_UNTRUSTED={"values_retained": False},
                        metadata_trust="operator supplied; not verified identity"))
            return comparison(rows)


def comparison(rows):
    features = {
        "verification_duration_ms": ("Server challenge issuance to submission; excludes time before issuance.",
            "Network delay, device load, accessibility and retries affect duration."),
        "request_event_ordering": ("Ordered server arrivals and lifecycle events, linked by request ordinal.",
            "Concurrent requests can complete out of arrival order."),
        "navigation_transitions": ("Route categories observed at the server.",
            "Prefetch, caches and back/forward cache obscure browser navigation."),
        "challenge_retries": ("Additional challenge issuances and submission attempts.",
            "Connectivity failures and expired challenges affect legitimate users."),
        "refresh_behavior": ("Repeated route categories; refresh cannot be identified conclusively.",
            "Reload, repeated fetch and new navigation can look identical."),
        "request_bursts": ("Interarrival intervals without a classification threshold.",
            "Page assets, parallel tabs and network batching create bursts."),
        "experiment_interaction": ("Existing experiment exposure and activation families.",
            "Tools/extensions may follow resources; informed automation may ignore them."),
        "session_continuity": ("Existing server validation and continuity observations.",
            "Cookie restrictions, expiry and fresh contexts interrupt continuity."),
        "optional_telemetry": ("Presence of browser field on parsed verification submissions.",
            "Script blocking and privacy tools can omit telemetry; claims can be spoofed."),
    }
    completed = [r for r in rows if r["completed"] and not r["SERVER_OBSERVED"]["truncated"]]
    humans = [r for r in completed if r["label"] == "manual-human"]
    bots = [r for r in completed if r["cohort"] in COHORTS[3:]]

    def observations(group, feature):
        result = []
        for row in group:
            events = row["SERVER_OBSERVED"]["events"]
            requests = [e for e in events if e["event"] == "request_started"]
            submissions = [e for e in events if e["event"] == "verification_submission"]
            if feature == "verification_duration_ms":
                value = [e["challenge_elapsed_ms"] for e in events if e["event"] == "verification_submitted"]
            elif feature == "request_event_ordering":
                value = [e["event"] for e in events]
            elif feature in ("navigation_transitions", "refresh_behavior"):
                value = [e["route"] for e in requests]
            elif feature == "challenge_retries":
                value = {"issuances": sum(e["event"] == "challenge_issued" for e in events), "submissions": len(submissions)}
            elif feature == "request_bursts":
                value = [round(b["elapsed_ms"] - a["elapsed_ms"], 3) for a, b in zip(requests, requests[1:])]
            elif feature == "experiment_interaction":
                value = [{"event": e["event"], "family": e.get("family")} for e in events if e["event"].startswith("experiment_")]
            elif feature == "session_continuity":
                value = [{k: e[k] for k in ("session_valid", "session_continuity")} for e in events if e["event"] == "access_decision"]
            else:
                value = [e["telemetry_present"] for e in submissions]
            result.append({"cohort": row["cohort"], "values": value})
        return result

    def duration_summary(group):
        values = [v for item in observations(group, "verification_duration_ms") for v in item["values"]]
        return {"n": len(values), "min": min(values) if values else None,
                "median": statistics.median(values) if values else None,
                "max": max(values) if values else None, "values": values}

    return dict(schema_version=1, exported_at=datetime.now(timezone.utc).isoformat(),
        verification_duration_distribution_ms={"human": duration_summary(humans), "automation": duration_summary(bots)},
        research_status="pending real manual samples and analysis" if not humans else "samples collected; detection research incomplete",
        cohorts=[dict(cohort=c, sample_size=sum(r["cohort"] == c for r in completed),
                      labeled_manual_samples=sum(r["cohort"] == c for r in humans),
                      status="collected" if any(r["cohort"] == c for r in completed) else "pending") for c in COHORTS],
        features={name: dict(description=description, human_observations=observations(humans, name),
            automation_observations=observations(bots, name), overlap="pending manual samples" if not humans else "requires analysis; no classifier inferred",
            sample_size={"human_runs": len(humans), "automation_runs": len(bots)},
            possible_false_positive_concerns=concern) for name, (description, concern) in features.items()}, runs=rows)


class MeasurementMiddleware:
    def __init__(self, app, recorder):
        self.app, self.recorder = app, recorder

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope)
        internal = request.url.path.startswith(PREFIX)
        if internal and (self.recorder is None or not local(request)):
            return await Response(status_code=404, headers=HEADERS)(scope, receive, send)
        if internal and request.method != "GET" and request.headers.get("origin") != str(request.base_url).rstrip("/"):
            return await Response(status_code=403, headers=HEADERS)(scope, receive, send)
        key = request.cookies.get(COOKIE)
        token = None
        if self.recorder and not internal and local(request):
            with self.recorder.lock:
                run = self.recorder.get(key)
                if run and not run["completed"]:
                    run["requests"] += 1
                    token = CURRENT.set((key, run["requests"]))
            if token:
                path = request.url.path
                route = (path if path in ("/challenge", "/challenge/client.js", "/challenge/verify") else
                         "experiment" if path.startswith("/challenge/") else
                         "protected_api" if path.startswith("/api/") else "protected_page")
                self.recorder.event("request_started", route=route, method=request.method)
        started = time.monotonic()

        async def observed_send(message):
            if token and message["type"] == "http.response.start":
                self.recorder.event("request_completed", status=message["status"],
                                    duration_ms=round((time.monotonic() - started) * 1000, 3))
            await send(message)
        try:
            await self.app(scope, receive, observed_send)
        finally:
            if token:
                CURRENT.reset(token)


def install(app, settings):
    recorder = Measurements() if settings.measurement_enabled else None
    app.add_middleware(MeasurementMiddleware, recorder=recorder)
    if recorder is None:
        return None
    app.state.measurements = recorder

    @app.get(PREFIX)
    def runner():
        options = ''.join(f'<option>{c}</option>' for c in COHORTS)
        return HTMLResponse(f'''<!doctype html><title>StopIn local measurement</title>
<h1>Manual browser measurement</h1>
<p>Start a fresh run, follow the protected page in another tab, and manually click Continue.
Visit the API, refresh, navigate back, then return here to finish. Record denied runs too.</p>
<form method="post" action="{PREFIX}/start"><select name="cohort">{options}</select><button>Start fresh run</button></form>
<p><a href="/private" target="_blank" rel="noopener">Open verification flow</a>
<a href="/api/private" target="_blank" rel="noopener">Visit protected API</a></p>
<form method="post" action="{PREFIX}/finish"><button>Finish current run</button></form>
<form method="post" action="{PREFIX}/label"><button>Label completed run manual-human</button></form>
<p>Label only runs you operated manually. Labels never grant access.</p>
<a href="{PREFIX}/export">Download sanitized comparison JSON</a>''', headers=HEADERS)

    @app.post(PREFIX + "/start")
    async def start(request: Request):
        from urllib.parse import parse_qs
        form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
        cohort = form.get("cohort", [""])[0]
        if cohort not in COHORTS:
            return Response(status_code=400, headers=HEADERS)
        with recorder.lock:
            previous = recorder.get(request.cookies.get(COOKIE))
            if previous and not previous["completed"]:
                return Response("Finish the current run first.", status_code=409, headers=HEADERS)
        response = RedirectResponse(PREFIX, status_code=303, headers=HEADERS)
        response.set_cookie(COOKIE, recorder.start(cohort), httponly=True,
                            samesite="strict", secure=settings.cookie_secure, max_age=7200)
        for name in ("gateway_session", "gateway_challenge_session"):
            response.delete_cookie(name, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
        return response

    @app.post(PREFIX + "/finish")
    def finish(request: Request):
        with recorder.lock:
            run = recorder.get(request.cookies.get(COOKIE))
            if not run or not run["requests"]:
                return Response(status_code=409, headers=HEADERS)
            run["completed"] = True
        return RedirectResponse(PREFIX, status_code=303, headers=HEADERS)

    @app.post(PREFIX + "/label")
    def label(request: Request):
        with recorder.lock:
            run = recorder.get(request.cookies.get(COOKIE))
            if not run or not run["completed"] or run["cohort"] not in COHORTS[:3]:
                return Response(status_code=409, headers=HEADERS)
            run["label"] = "manual-human"
        return RedirectResponse(PREFIX, status_code=303, headers=HEADERS)

    @app.get(PREFIX + "/export")
    def export():
        return JSONResponse(recorder.export(), headers={**HEADERS,
            "Content-Disposition": 'attachment; filename="human-vs-automation-results.json"'})
    return recorder
