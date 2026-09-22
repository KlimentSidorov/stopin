# AI Access Gateway

Milestone 10 adds three randomized experiment families and a five-strategy
Chromium harness. Latest local verification (2026-09-20): **145 gateway tests
passed, 1 real-Redis test skipped**, plus **3 dashboard tests passed**.
The StopIn-aware adversary and telemetry-omitting explorer both obtained
protected content; these are documented bypasses, not detection successes.
See [adaptive experiment architecture and measured results](docs/adaptive-agent-experiments.md)
and the [recorded result matrix](docs/adaptive-agent-results.json).

Milestone 9 adds an experimental Agent Interaction Challenge on the existing
session tripwire. Local verification (2026-09-20): **98 passed, 1 skipped**
(real Redis requires `TEST_REDIS_URL`), plus **3 dashboard tests passed**.
See [experiment results and limitations](docs/agent-interaction-challenge.md).
Resource exploration can activate the trap; ordinary Playwright and the tested
report-omission variant can still obtain access. Activation does not prove AI.

Milestones 1-7 are complete locally: gateway, sessions, challenge client, adversarial
tests, signal/policy engine, protected Next.js origin integration, and dashboard.
Milestone 8 gateway hardening is implemented; hosted rollout verification remains pending.
Milestone 8 verification (2026-09-19): **82 passed, 1 skipped** (real Redis requires
`TEST_REDIS_URL`); runtime dependency audit found no known vulnerabilities.
See [production setup and limitations](docs/production.md) for Railway, Redis,
database maintenance, metrics, rate limits, key rotation and tenant boundaries.
Production origin rollout remains pending; the real website has not been changed.

## Milestone 7: dashboard

The Next.js + Tailwind dashboard lives in `../Stopin-Dashboard`. Run `npm install`
and `npm run dev` there, then open http://127.0.0.1:3001. Add a site using the same
ID as `GATEWAY_SITE_ID`, and configure its protected origin and policy.

Set `GATEWAY_DASHBOARD_DB` to the absolute path of `../Stopin-Dashboard/data/stopin.db`
before starting the gateway. Real decisions, reason codes, and signals appear in
the event explorer; saved origins and policies apply on the next request.
Leaving this variable unset preserves the existing gateway behavior.

The console includes site settings, traffic charts, decision filters, request
inspection, strictness, ordered route rules, and integration instructions.
SQLite is shared locally. The dashboard supports a remote libSQL/Turso URL, but
the Python bridge remains local SQLite for now. See the dashboard README for
setup, policy semantics, validation, and production-hardening boundaries.

## Run

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
$env:GATEWAY_ORIGIN_URL = "http://localhost:9000"
$env:GATEWAY_SITE_ID = "local"
# Configure this same secret on the guarded origin process.
$env:GATEWAY_ORIGIN_SECRET = python -c "import secrets; print(secrets.token_urlsafe(32))"
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
In development, restarting the worker revokes access. Redis-backed deployments
share sessions and revocation across workers. The optional `GATEWAY_DEV_ACCESS_TOKEN`
bypass is disabled by default; enable it explicitly only for development.

This nonce round trip demonstrates the access protocol; automation can complete
it. It is not human detection. The prototype signal engine is described below.
Development stores remain in memory: use one worker without Redis. Production
requires Redis, explicit keys, secure cookies, an allowed-host list and a persisted
configuration database. Apply the origin guard and hosting restrictions
before deployment to prevent direct bypass.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider
```

Tests cover origin isolation, valid navigation/API access, tampering, expiry,
site binding, revocation, unknown sessions, browser binding, one-time use,
attempt limits, input validation, and safe return destinations.

## Milestone 4: adversarial clients

Verified on 2026-09-18: **35 tests passed, 0 skipped**, including Requests and
real Chromium challenge automation and network interception. Two dependency
deprecation warnings remain. Milestones 1-4 are marked DONE in the build plan.
The network probe captures response bodies before navigation discards them, and
browser waits use locators compatible with the gateway Content Security Policy.

Install the optional test tools and Chromium, then run the full suite:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test,adversarial]"
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -rs
```

The adversarial pytest suite starts an isolated gateway and test origin on ephemeral
loopback ports, disables the development bypass, records origin requests, and
shuts both servers down afterward. It checks raw HTTP blocking, challenge replay,
concurrent verification, forged/expired/wrong-site tokens, client claims, and
legacy header bypass attempts. Chromium tests inspect DOM, navigation, fetch and
XHR responses before and after clicking Continue. The Requests and Chromium tests
are reported as skipped when their Python dependencies are absent. Once Playwright
is installed, a missing Chromium executable fails the tests. Completion requires
all tests to pass without these skips.

For a separately running **test** gateway/origin, the clients also run independently:

```powershell
.\.venv\Scripts\python.exe test-agents/requests_test.py --url http://127.0.0.1:8000
.\.venv\Scripts\python.exe test-agents/playwright_test.py --url http://127.0.0.1:8000 --marker "known-protected-text"
.\.venv\Scripts\python.exe test-agents/browser_network_test.py --url http://127.0.0.1:8000 --marker "known-protected-text"
.\.venv\Scripts\python.exe test-agents/replay_test.py --url http://127.0.0.1:8000
```

These probes expect protected `/private` and `/api/private` routes, no development
bypass, and the supplied marker in both origin responses. They print JSON observations
including retrieved response bodies; use test data. They fail with a nonzero exit
code if assertions fail. Browser automation is expected to complete the current
nonce challenge. Captured valid access cookies are reusable bearer credentials
until expiry/revocation; consumed challenges cannot be reused to issue a new one.
Known-crawler blocking is not asserted yet: that policy belongs to later milestones.

## Milestone 5: signal and policy engine

`gateway/detection/` collects grouped evidence; `gateway/policies/evaluator.py`
makes deterministic access decisions. The schema separates request, browser,
behavior, tripwire, rate, crawler, and session observations. Crawler identity is
explicitly unverified; verified crawler rules are future work.

- Request: navigation eligibility, route category, and inconsistent Fetch Metadata.
- Browser: optional JavaScript, WebDriver, and elapsed-time reports. These are
  untrusted observations and can be spoofed; they never establish access.
- Session/behavior: validated credentials, continuity, previous route category,
  server-measured verification duration, and failed verification counts.
- Rate: more than 30 requests per 10 seconds within tracked session evidence.
- Tripwire: a random per-session URL returned in challenge JSON. Normal challenge
  code ignores it; no hidden interactive controls are added to the page. Activation
  requires the matching challenge cookie or a valid access session, returns no
  protected data, and records an OBSERVE event.

A single browser hint, tripwire hit, header inconsistency, or burst does not block
an otherwise valid session. Two signal groups require fresh verification for HTML
navigation (CHALLENGE) or deny API/non-navigation requests (BLOCK). A tripwire hit
combined with a burst blocks access. Invalid credentials always block. Verification
also evaluates evidence before issuing a session. Reason codes and grouped signal
snapshots are logged; no raw browser strings, IPs, tokens, nonces, or origin bodies
are added to the signal logs. A CHALLENGE returns HTTP 200 with challenge HTML only.

The thresholds are prototype rules, not calibrated AI detection probabilities.
Ordinary Playwright can still solve the challenge, and an attacker can omit browser
reports or reset their session. Evidence is worker-local, expires after 10 minutes,
is capped at 10,000 sessions and 101 request timestamps per session, and can be
evicted. This is not IP/global rate limiting. Distributed enforcement, production
hardening, and broader accessibility/false-positive measurement remain future work.

## Milestone 6: origin security

The gateway now requires `GATEWAY_ORIGIN_SECRET` before proxying allowed requests.
The origin must independently enforce that same credential. A guarded local Next.js fixture, reusable ASGI guard,
and Python demo origin are included. See [origin setup and deployment
requirements](docs/origin-security.md). Existing origins must install equivalent
protection; setting the gateway variable alone does not prevent direct access.

## Milestone 11: manual browser measurement

An explicitly enabled development-only runner at `/__measurement` collects
sanitized server observations from real manual runs and the existing Playwright
strategies. See [human vs automation measurement](docs/human-vs-automation-measurement.md)
for setup, post-run labeling, exports and the 15-run automation pilot. Nine completed operator-confirmed manual Chrome runs are now recorded, with protected
requests failing with 503; Firefox/mobile remain pending. Passing implementation
tests does not establish human/automation detection.
