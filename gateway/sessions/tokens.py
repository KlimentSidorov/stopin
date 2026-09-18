import base64
import hashlib
import hmac
import json
import time


def create_access_token(session_id: str, secret: str, lifetime_seconds: int = 300,
                        site_id: str = "test-site") -> str:
    now = int(time.time())
    payload = {"session_id": session_id, "site_id": site_id, "issued_at": now,
               "expires_at": now + lifetime_seconds, "verification_version": 1}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode("ascii")
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def verify_access_token(token: str, secret: str, site_id: str = "test-site") -> str | None:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))
        if not isinstance(payload, dict):
            return None
        now = int(time.time())
        if (type(payload.get("expires_at")) is not int
                or type(payload.get("issued_at")) is not int
                or not payload["issued_at"] <= now < payload["expires_at"]
                or payload.get("site_id") != site_id
                or type(payload.get("verification_version")) is not int
                or payload["verification_version"] != 1
                or not isinstance(payload.get("session_id"), str)
                or not payload["session_id"]):
            return None
        return payload["session_id"]
    except (ValueError, TypeError, UnicodeError):
        return None
