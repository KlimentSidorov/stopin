# Origin security (Milestone 6)

The origin must validate the gateway credential before serving any protected
HTML, API, static-file, or other response. Setting a secret only on the gateway
cannot protect an origin which does not enforce it.

## Local Next.js + FastAPI demonstration

The fixture is `examples/nextjs-origin/`. Its custom Node server binds only to
`127.0.0.1`, checks the shared secret **before** the Next.js handler, and covers
HTML, route handlers, public files, and generated `/_next/` assets. Do not run
`next start` or `next dev` directly: that would bypass this server guard.

Install and build once from the repository root:

```powershell
npm --prefix examples/nextjs-origin ci
npm --prefix examples/nextjs-origin run build
```

Generate one random secret:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set the **same generated value** in each terminal below. Keep it separate from
GATEWAY_TOKEN_SECRET and do not commit it. Terminal 1 (origin):

```powershell
$env:GATEWAY_ORIGIN_SECRET = "paste-the-generated-value"
$env:PORT = "9000"
npm --prefix examples/nextjs-origin start
```

Terminal 2 (gateway):

```powershell
$env:GATEWAY_ORIGIN_SECRET = "paste-the-same-generated-value"
$env:GATEWAY_ORIGIN_URL = "http://127.0.0.1:9000"
$env:GATEWAY_DEV_ACCESS_TOKEN = ""
.\.venv\Scripts\python.exe -m uvicorn gateway.app:create_app --factory --host 127.0.0.1 --port 8000
```

Direct requests to `http://127.0.0.1:9000/private`, `/api/private`, and
`/private.txt` return empty 403 responses, including when carrying a valid gateway
session cookie. Visit `http://127.0.0.1:8000/private`, complete verification, and
the gateway retrieves protected content. Raw unauthenticated gateway requests
remain blocked. The origin refuses to start with an absent/short secret; an
authorized gateway request with missing/invalid origin configuration returns
empty 503 without an upstream request. A mismatched secret returns empty 403.

Run the acceptance suite (it starts and stops its own servers on ephemeral ports):

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -rs
```

Next.js tests skip if Node or the compiled fixture is missing. Milestone 6 local
acceptance requires these tests to run without skips. Rebuild after editing the
fixture app. A smaller ASGI demonstration is also available via
`uvicorn gateway.origin.demo:create_origin --factory --host 127.0.0.1 --port 9000`.

## Existing Python ASGI origin

Wrap the entire application; start the wrapped export, not the unprotected app:

```python
import os
from gateway.origin.protection import OriginProtection
from my_application import app as application

app = OriginProtection(application, os.environ["GATEWAY_ORIGIN_SECRET"])
```

The guard requires exactly one matching `X-Gateway-Origin-Secret` header, using
constant-time comparison. It strips the header before invoking application code.
It covers all HTTP routes/methods and rejects unauthorized WebSocket handshakes.
The gateway itself does not proxy WebSockets. No route is publicly exempted.

The Next.js fixture demonstrates a self-hosted custom-server boundary. Follow
the [Next.js custom server documentation](https://nextjs.org/docs/app/guides/custom-server)
when adapting it. Production hosting may instead require a private network or
guard at a reverse proxy; the local fixture does not change the production site.
Confirm the deployment platform before choosing that integration.

## Deployment requirements

- Bind the origin to loopback when both processes share a host, or use a private
  network/firewall that permits only the gateway. Do not publish an alternate
  unguarded listener, hostname, preview deployment, static bucket, or API endpoint.
- Use HTTPS with certificate validation between separate hosts. Plain HTTP is
  only for local loopback development or an appropriately secured private transport.
- Store a random secret of at least 32 printable ASCII characters in both servers'
  secret configuration. Never place it in public/client environment variables,
  URLs, source control, response bodies, or access-log header dumps.
- Keep `GATEWAY_DEV_ACCESS_TOKEN` empty outside development. Rotate origin secrets
  on both sides together; coordination/key rotation is future hardening work.
- The proxy overwrites inbound gateway headers, suppresses gateway response headers,
  and never follows origin redirects with the secret. If a redirect sends a browser
  to the origin directly, that request is denied; configure public links using the
  gateway hostname. This gateway does not rewrite application URLs.

## Evidence and scope

The automated suite uses real loopback FastAPI and Next.js origins with guards active.
It checks direct HTML/API access, forged headers, gateway-cookie reuse at the origin,
Chromium direct navigation, public/generated static assets, and successful verified
gateway access. Unit tests cover
all-route guarding, duplicate credentials, fail-closed configuration, credential
stripping, and redirect isolation. This verifies the included integration, not an
external hosting firewall or an origin application outside this workspace.
