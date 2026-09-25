import hmac

from gateway.detection.crawler_identity import classify_user_agent
from gateway.detection.signals import Signals
from gateway.sessions.tokens import verify_access_token


def collect_signals(request, settings, sessions, evidence):
    token = request.cookies.get("gateway_session")
    session_id = verify_access_token(token, settings.token_secret, settings.site_id,
                                     settings.token_previous_secrets) if token else None
    valid = bool(session_id and sessions.valid(session_id, settings.site_id))
    binding = request.cookies.get("gateway_challenge_session")
    evidence_id = binding if request.url.path == "/challenge/verify" else session_id or binding
    record = evidence.get(evidence_id)
    category = "api" if request.url.path.startswith("/api/") else "page"
    if record and request.url.path != "/challenge/verify":
        evidence.lifecycle(evidence_id, "protected_" + category + "_requested")
    count, previous = evidence.observe(record, category) if record else (0, None)
    # Redis mutations operate on fresh records; collect the committed sequence.
    record = evidence.get(evidence_id)
    interaction = evidence.interaction_signals(record) if record else {}
    mode = request.headers.get("sec-fetch-mode")
    destination = request.headers.get("sec-fetch-dest")
    fetch_site = request.headers.get("sec-fetch-site")
    user_agent = request.headers.get("user-agent", "")
    html_navigation = request.method == "GET" and "text/html" in request.headers.get("accept", "")
    # Modern Chromium/Edge/Chrome navigations provide Fetch Metadata and client hints.
    # This is a transparent access signal, not proof of humanity: a capable client can
    # reproduce these headers. It is intentionally combined with crawler policy below.
    browser_navigation = bool(
        html_navigation
        and mode == "navigate"
        and destination == "document"
        and fetch_site in ("none", "same-origin", "same-site")
        and request.headers.get("sec-fetch-user") == "?1"
        and request.headers.get("sec-ch-ua")
        and "mozilla/5.0" in user_agent.lower()
    )
    inconsistent = mode == "navigate" and destination not in (None, "document", "iframe")
    development = request.headers.get("x-gateway-access-token", "")
    return Signals(
        request={"html_navigation": html_navigation,
                 "browser_navigation": browser_navigation,
                 "header_inconsistent": inconsistent, "route_category": category},
        browser=dict(record.browser) if record else {},
        behavior={"previous_category": previous,
                  "verification_ms": record.verification_ms if record else None,
                  "verification_failures": record.verification_failures if record else 0,
                  "browser_report_supplied": record.browser_report_supplied if record else False,
                  **interaction.get("behavior", {})},
        tripwires=interaction.get("tripwires", {"activated": False}),
        rate={"requests_10s": count, "burst": count > 30},
        crawler=classify_user_agent(user_agent),
        session={"id": session_id if valid else None, "valid": valid,
                 "invalid_token": bool(token and not valid),
                 "continuity": record is not None,
                 "development": bool(settings.dev_access_token and hmac.compare_digest(
                     development.encode(), settings.dev_access_token.encode()))})
