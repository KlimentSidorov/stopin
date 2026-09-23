"""Sanitized server-observed request metadata for the research evaluator.

This module intentionally records only a small allowlist of HTTP metadata. It does
not record bodies, cookies, authorization values, IP addresses, query strings, or
opaque evaluation capabilities. Observations are research evidence, never identity.
"""
from __future__ import annotations

from typing import Mapping

SAFE_VALUE_HEADERS = (
    "accept",
    "accept-language",
    "accept-encoding",
    "user-agent",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "purpose",
    "sec-purpose",
    "x-requested-with",
)
SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "proxy-authorization", "set-cookie",
    "x-forwarded-for", "forwarded", "x-real-ip", "cf-connecting-ip",
}
MAX_VALUE_LENGTH = 512


def _clean(value: str) -> str:
    value = " ".join(value.split())
    return value[:MAX_VALUE_LENGTH]


def observe_request(request, *, route: str) -> dict:
    """Return a bounded observation safe to expose on the authenticated control plane."""
    names = sorted({name.lower() for name in request.headers
                    if name.lower() not in SENSITIVE_HEADER_NAMES})
    values = {}
    for name in SAFE_VALUE_HEADERS:
        value = request.headers.get(name)
        if value:
            values[name] = _clean(value)
    return {
        "route": route,
        "method": request.method,
        "http_version": request.scope.get("http_version", ""),
        "header_names": names[:64],
        "headers": values,
        "has_cookie": bool(request.headers.get("cookie")),
        "has_authorization": bool(request.headers.get("authorization")),
    }


def summarize_observations(observations: list[Mapping]) -> dict:
    """Describe observable HTTP behavior without claiming client identity."""
    routes = [str(item.get("route", "")) for item in observations]
    return {
        "request_count": len(observations),
        "routes": routes,
        "script_requested": "script" in routes,
        "completion_requested": "complete" in routes,
        "optional_requested": "optional" in routes,
        "protected_requested": "protected" in routes,
        "cookie_seen_after_entry": any(bool(item.get("has_cookie"))
                                       for item in observations[1:]),
    }
