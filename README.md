# AI Access Gateway

Milestones 1?3 are implemented: reverse proxy, one-time challenges, signed access
sessions, and a minimal browser challenge client.

## Run

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
$env:GATEWAY_ORIGIN_URL = "http://localhost:9000"
$env:GATEWAY_SITE_ID = "local"
$env:GATEWAY_TOKEN_SECRET = python -c "import secrets; print(secrets.token_urlsafe(32))"
uvicorn gateway.app:app --port 8000
```

Run your protected application separately on port 9000. The gateway must not
point to its own port. Environment variables are read directly; `.env` is not
automatically loaded. See `.env.example`. Use `GATEWAY_COOKIE_SECURE=true` on HTTPS.

Open `http://localhost:8000/your-page` in a browser. An unverified HTML GET receives
only the challenge page. Click Continue: the client requests a fresh challenge,
submits it for server verification, receives an HttpOnly signed cookie, and
navigates to the original local path and query. `/challenge?next=/your-page` also
provides explicit verification or recovery after a session expires. External
return destinations are rejected. Verification failures offer a retry.

API/raw requests and non-GET requests without access receive an empty 403.
Invalid or expired cookies also receive 403. Valid sessions allow both pages
and API requests. Responses are marked no-store to prevent shared cache leaks.
Gateway credentials are stripped before proxying to the origin.

## Session security

Challenges use random IDs and nonces, expire after five minutes, are bound to a
server-generated HttpOnly browser cookie, and permit one verification attempt.
Successful challenges are consumed. Access tokens include session ID, site ID,
issue/expiry times, and verification version, authenticated with HMAC-SHA256.
Every protected request checks both the token and active server-side session.
Restarting the worker revokes access. The optional `GATEWAY_DEV_ACCESS_TOKEN`
bypass is disabled by default; enable it explicitly only for development.

This nonce round trip demonstrates the access protocol; automation can complete
it. It is not human detection. Detection remains a later milestone. The stores
are in memory: use one worker for now. Distributed storage, cleanup/capacity
limits, origin lockdown, rate limiting, and production hardening remain future
work. The origin must be restricted before deployment to prevent direct bypass.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider
```

Tests cover origin isolation, valid navigation/API access, tampering, expiry,
site binding, revocation, unknown sessions, browser binding, one-time use,
attempt limits, input validation, and safe return destinations.
