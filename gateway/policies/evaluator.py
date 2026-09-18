import hmac
from enum import StrEnum

from fastapi import Request

from gateway.config import Settings
from gateway.sessions.store import InMemorySessionStore
from gateway.sessions.tokens import verify_access_token


class Decision(StrEnum):
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


def evaluate_request(request: Request, settings: Settings,
                     sessions: InMemorySessionStore) -> tuple[Decision, list[str]]:
    development_token = request.headers.get("x-gateway-access-token", "")
    if (settings.dev_access_token and hmac.compare_digest(
            development_token.encode(), settings.dev_access_token.encode())):
        return Decision.ALLOW, ["valid_development_token"]
    token = request.cookies.get("gateway_session")
    if token:
        session_id = verify_access_token(token, settings.token_secret, settings.site_id)
        if session_id and sessions.valid(session_id, settings.site_id):
            return Decision.ALLOW, ["valid_verified_session"]
        return Decision.BLOCK, ["invalid_session"]
    if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
        return Decision.CHALLENGE, ["new_session"]
    return Decision.BLOCK, ["missing_session"]
