"""Install on the origin, outside all routes and static-file handlers."""
import secrets

from starlette.responses import Response

HEADER = b"x-gateway-origin-secret"


def validate_secret(secret: str) -> bytes:
    if len(secret) < 32 or not secret.isascii() or not secret.isprintable():
        raise ValueError("Origin secret must contain at least 32 printable ASCII characters")
    return secret.encode("ascii")


class OriginProtection:
    def __init__(self, app, secret: str):
        self.app = app
        self.secret = validate_secret(secret)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        values = [value for key, value in scope.get("headers", []) if key.lower() == HEADER]
        if len(values) != 1 or not secrets.compare_digest(values[0], self.secret):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await Response(status_code=403, headers={"cache-control": "no-store"})(
                    scope, receive, send)
            return
        # Do not expose the gateway credential to downstream app code or header echoes.
        scope = dict(scope)
        scope["headers"] = [(key, value) for key, value in scope["headers"] if key.lower() != HEADER]
        await self.app(scope, receive, send)
