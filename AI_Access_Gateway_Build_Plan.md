# AI / Automation Access Gateway --- Build & Test Plan

## 1. Goal

Build a production-oriented gateway that sits **before** a protected
website or API and decides whether a request should be:

-   **ALLOW** --- proxy the request to the protected origin.
-   **CHALLENGE** --- return only a verification challenge; do not
    return origin content.
-   **BLOCK** --- return `403 Forbidden` with no protected content.

The product goal is **not** to promise perfect detection of Playwright
or AI. A sufficiently capable automated browser can imitate human
behavior. The goal is to combine independent signals, make automated
extraction harder and more expensive, keep false positives measurable,
and give website owners control over automated/AI access.

## 2. Core Security Rule

**Protected HTML/API data must never be sent before the gateway grants
access.**

Bad:

``` text
Browser -> Next.js -> protected HTML -> JavaScript hides it
```

Good:

``` text
Browser
   |
   v
Gateway
   |
   +-- untrusted -> challenge / 403
   |
   +-- trusted -> protected origin
```

The protected origin must eventually be inaccessible directly, otherwise
an extractor can bypass the gateway.

------------------------------------------------------------------------

## 3. Proposed Repository

``` text
ai-access-gateway/
|
|-- gateway/                    # Python gateway/detection service
|   |-- app.py                  # HTTP entry point
|   |-- config.py
|   |
|   |-- proxy/
|   |   |-- origin_proxy.py
|   |
|   |-- challenges/
|   |   |-- generator.py
|   |   |-- verifier.py
|   |
|   |-- detection/
|   |   |-- engine.py
|   |   |-- request_signals.py
|   |   |-- browser_signals.py
|   |   |-- behavior_signals.py
|   |   |-- crawler_identity.py
|   |
|   |-- sessions/
|   |   |-- store.py
|   |   |-- tokens.py
|   |
|   |-- policies/
|   |   |-- evaluator.py
|   |
|   |-- logging/
|       |-- events.py
|
|-- challenge-client/           # JS executed on challenge page
|   |-- src/
|
|-- dashboard/                  # Next.js customer dashboard
|   |-- app/
|
|-- sdk/
|   |-- nextjs/                 # Future Next.js integration
|
|-- test-agents/
|   |-- requests_test.py
|   |-- playwright_test.py
|   |-- browser_network_test.py
|
|-- tests/
|   |-- unit/
|   |-- integration/
|   |-- adversarial/
|
|-- docs/
|   |-- architecture.md
|   |-- protocol.md
|   |-- threat-model.md
|
|-- .env.example
|-- docker-compose.yml
|-- README.md
```

## 4. Request Flow

``` text
Internet
   |
   v
Gateway
   |
   +--> inspect request/session
   |
   +--> known policy decision?
   |       |
   |       +--> BLOCK -> 403
   |
   +--> valid signed session?
   |       |
   |       +--> YES -> proxy to origin
   |
   +--> challenge
           |
           v
     collect signals
           |
           v
     server verification
           |
      +----+----+
      |         |
    ALLOW     BLOCK
      |         |
 signed token  403
      |
      v
 protected origin
```

## 5. Phase 0 --- Establish Baseline

We already proved these concepts manually:

-   `requests` can retrieve initial HTML.
-   An HTML parser can extract page text.
-   Client-only JavaScript can prevent a basic HTTP parser from seeing
    rendered content.
-   Playwright/Chromium can execute JavaScript and read the resulting
    DOM.
-   Playwright can observe API/network responses directly.
-   A server-side API can return `403` instead of protected data.

Keep these scripts. They become our first adversarial test clients.

### Acceptance test

``` text
requests_test.py -> records exactly what an unauthenticated HTTP client can retrieve
playwright_test.py -> records exactly what Chromium automation can retrieve
```

------------------------------------------------------------------------

## 6. Phase 1 --- Python Reverse Proxy Gateway

### Build

Use Python for the gateway. Start with FastAPI/Starlette or another
small ASGI stack.

Gateway receives the request first:

``` text
GET customer.example/products
          |
          v
       Gateway
          |
          v
    policy decision
```

Initially implement:

-   Incoming request handling
-   Origin configuration
-   Reverse proxying
-   `ALLOW`
-   `BLOCK`
-   Structured request/event logging
-   Protect both pages and API routes

### First policy

For development:

``` text
valid session -> ALLOW
no session    -> BLOCK
```

No detection yet.

### Acceptance tests

1.  Direct request without session returns `403`.
2.  `403` response contains none of the origin's protected text.
3.  Valid development token proxies to the origin and returns `200`.
4.  API endpoints are protected too.

------------------------------------------------------------------------

## 7. Phase 2 --- Challenge State

Never use a permanent/static challenge.

For each untrusted session generate:

``` text
challenge_id
random nonce
created_at
expires_at
attempt_count
status
session_id
```

Use cryptographically secure randomness.

Example lifecycle:

``` text
NEW -> ISSUED -> VERIFIED -> CONSUMED
                 |
                 +-> FAILED / EXPIRED
```

Properties:

-   One-time use
-   Short expiration
-   Bound to a server-side session
-   Replay rejected
-   Attempt limits
-   No protected origin data embedded in the challenge

### Acceptance tests

-   Reusing a consumed challenge fails.
-   Expired challenge fails.
-   Random challenge ID fails.
-   Challenge from session A cannot authorize session B.

------------------------------------------------------------------------

## 8. Phase 3 --- Signed Access Sessions

After successful verification, the server issues a short-lived signed
session/token.

Conceptual claims:

``` json
{
  "session_id": "...",
  "site_id": "...",
  "issued_at": "...",
  "expires_at": "...",
  "verification_version": 1
}
```

Never trust a browser-provided `isHuman=true`.

The server verifies the signature and server-side state before proxying
protected requests.

### Acceptance tests

-   Modified token -\> `403`.
-   Expired token -\> challenge/`403`.
-   Token for another site -\> `403`.
-   Valid token -\> origin request allowed.

------------------------------------------------------------------------

## 9. Phase 4 --- Signal Collection

Do **not** make a single signal equal "AI."

Create independent signal groups.

### Request/network signals

Examples:

-   Request/header consistency
-   Request ordering
-   Rate and burst patterns
-   Session continuity
-   Known crawler identification
-   Network/reputation information where legally and operationally
    appropriate

### Browser/challenge signals

Collect only what is necessary for bot/access-control purposes.

Examples:

-   Challenge JavaScript executed
-   Browser environment consistency
-   Challenge lifecycle consistency
-   Timing measurements
-   Session continuity

### Behavioral signals

Examples:

-   Navigation sequence
-   Impossible/unexpected request order
-   Extremely rapid repeated actions
-   Interaction with decoy/tripwire paths

**Important:** accessibility technology, browser extensions, privacy
tools, unusual devices, and legitimate automation can produce unusual
signals. No single signal should automatically classify a person as AI.

------------------------------------------------------------------------

## 10. Phase 5 --- Agent Tripwires

This is the experimental differentiator.

Create actions/resources that ordinary visitors should not need to
invoke during the expected UI flow.

A tripwire should:

-   Never contain protected data.
-   Have a unique per-session identifier.
-   Record server-side activation.
-   Add evidence to the risk decision.
-   Not automatically block solely because it fired.
-   Be tested for accessibility and false positives.

Example:

``` text
challenge
   |
   +-- expected interaction
   |
   +-- instrumented decoy -> event recorded
```

Do not rely on the tripwire being secret. Assume automated systems
eventually know the design.

### Acceptance test

Our Playwright test intentionally triggers a test tripwire and the event
appears in gateway logs.

------------------------------------------------------------------------

## 11. Phase 6 --- Risk / Policy Engine

Separate **signals** from **policy**.

Input:

``` python
signals = {
    "request": {...},
    "browser": {...},
    "behavior": {...},
    "tripwires": {...},
    "rate": {...},
    "crawler": {...},
    "session": {...}
}
```

Output:

``` text
ALLOW
CHALLENGE
BLOCK
```

Also store reason codes:

``` text
CHALLENGE:
- new_session
- inconsistent_browser_signals

BLOCK:
- known_disallowed_crawler
- invalid_token
- excessive_automation_pattern
```

Do not expose fake certainty such as "99.8% AI" unless we later have
calibrated data that actually supports that interpretation.

------------------------------------------------------------------------

## 12. Phase 7 --- Known Crawler Identity & Customer Rules

Customers need explicit policies.

Example:

``` text
Google Search crawler    ALLOW
Known AI crawler         BLOCK
Unknown automation       CHALLENGE
Verified human session   ALLOW

/blog/*                  permissive
/products/*              normal
/api/private/*           strict
```

Crawler identity should not rely only on a self-declared User-Agent
where stronger verification is available.

------------------------------------------------------------------------

## 13. Phase 8 --- Protect the Origin

This is mandatory before calling the gateway production-ready.

Bad architecture:

``` text
public -> gateway -> origin.example.com
                    ^
                    |
              attacker goes here
```

Desired:

``` text
public internet
      |
      v
   gateway
      |
      v
private/restricted origin
```

Possible approaches depend on hosting:

-   Firewall/security-group restrictions
-   Private network
-   Shared origin secret validated at the origin
-   Platform-specific edge/origin protection

### Acceptance test

Knowing the origin hostname/IP must not be enough to retrieve protected
content directly.

------------------------------------------------------------------------

## 14. Phase 9 --- Adversarial Test Harness

Every defense must be tested against our own clients.

### Test clients

#### A. Basic HTTP

``` text
requests
```

Tests raw HTTP extraction.

#### B. Basic Playwright

``` text
Chromium + JavaScript + DOM
```

Tests browser rendering.

#### C. Network-aware Playwright

Observes:

``` text
fetch
XHR
JSON responses
navigation
cookies
```

#### D. Challenge interaction test

Attempts normal challenge interactions.

#### E. Replay test

Attempts reuse of:

-   challenge IDs
-   tokens
-   cookies
-   captured requests

### Test matrix

``` text
                         Expected
requests/no session      BLOCK
Playwright/no session    CHALLENGE
invalid token            BLOCK
expired token            BLOCK
replayed challenge       BLOCK
valid verified session   ALLOW
known blocked crawler    BLOCK
```

Every bug becomes a regression test.

------------------------------------------------------------------------

## 15. Phase 10 --- Logging & Measurement

Before advanced detection, build good observability.

For each gateway decision record:

``` text
timestamp
site_id
request_id
session_id
route category
decision
reason codes
challenge version
signals used
latency
```

Avoid logging protected page bodies or unnecessary personal data.

We need to measure:

-   Challenge rate
-   Block rate
-   Verification success
-   False positives reported
-   Gateway latency
-   Origin latency
-   Detection rule performance

Without measurement, we cannot know whether detection improvements
actually work.

------------------------------------------------------------------------

## 16. Phase 11 --- Next.js Dashboard

Only after the gateway works.

Initial dashboard:

### Sites

-   Add domain
-   Origin configuration
-   Integration status

### Traffic

-   Allowed
-   Challenged
-   Blocked
-   Known crawlers
-   Suspicious automation

### Policies

-   Route rules
-   Crawler rules
-   Strictness
-   API protection

### Event inspector

For a request:

``` text
Decision: BLOCK

Reasons:
- invalid session
- tripwire activation
- abnormal request sequence
```

### Developer section

-   API keys
-   Integration instructions
-   Test mode
-   Webhooks later

------------------------------------------------------------------------

## 17. Phase 12 --- Integration Options

### MVP

Customer runs/integrates gateway in front of an origin.

### Next.js SDK

Future developer experience:

``` ts
import { protect } from "@gateway/next";

export const middleware = protect({
  mode: "strict"
});
```

### Edge product

Long-term:

``` text
DNS
 |
 v
Our edge network
 |
 v
Customer origin
```

This is the strongest product form because the decision happens before
the protected application receives the public request.

------------------------------------------------------------------------

## 18. Phase 13 --- Performance & Reliability

A gateway becomes part of every protected request, so performance
matters.

Targets to establish and measure:

-   Very low decision latency for already-verified sessions
-   No challenge on every page navigation
-   Short-lived cached verification state
-   Gateway failure strategy configurable per customer
-   Horizontal scaling
-   Rate limiting
-   Health checks
-   Metrics
-   Safe key rotation

Do not optimize before measuring.

------------------------------------------------------------------------

## 19. Phase 14 --- Security Review

Before real customers:

-   Threat model
-   Replay protection review
-   Token/key handling review
-   Origin bypass review
-   SSRF protections in reverse proxy
-   Header/cookie forwarding review
-   Request smuggling/desync considerations
-   Rate-limit abuse tests
-   Challenge abuse tests
-   Dependency scanning
-   Secrets management
-   Logging/privacy review

The gateway itself becomes security infrastructure and must be treated
accordingly.

------------------------------------------------------------------------

## 20. Development Order

Follow this order. Do not jump directly to advanced fingerprinting.

### Milestone 1 --- Gateway foundation

``` text
[x] Create repository
[x] Python virtual environment
[x] Gateway HTTP server
[x] Configure one protected origin
[x] Reverse proxy request
[x] ALLOW/BLOCK policy
[x] Empty 403 response
[x] Structured logs
```

### Milestone 2 --- Session security

``` text
[x] Challenge store
[x] Cryptographic nonce
[x] Expiration
[x] One-time consumption
[x] Signed access token/session
[x] Replay tests
```

### Milestone 3 --- Challenge client

``` text
[x] Minimal challenge page
[x] Challenge submission endpoint
[x] Server verification
[x] Session issuance
[x] Protected navigation
```

### Milestone 4 --- Attack it

``` text
[ ] requests_test.py
[ ] playwright_test.py
[ ] network interception test
[ ] challenge automation test
[ ] replay test
```

### Milestone 5 --- Detection engine

``` text
[ ] Signal schema
[ ] Request signals
[ ] Browser/session signals
[ ] Behavior signals
[ ] Tripwire prototype
[ ] Reason codes
[ ] ALLOW / CHALLENGE / BLOCK evaluator
```

### Milestone 6 --- Origin security

``` text
[ ] Prevent direct origin access
[ ] Protect HTML
[ ] Protect API
[ ] Test origin bypass
```

### Milestone 7 --- Dashboard

``` text
[ ] Site configuration
[ ] Traffic overview
[ ] Decisions
[ ] Reason codes
[ ] Policy configuration
```

### Milestone 8 --- Production hardening

``` text
[ ] Redis/distributed session state
[ ] Database
[ ] Metrics
[ ] Rate limiting
[ ] Key rotation
[ ] Multi-tenant isolation
[ ] Deployment automation
[ ] Security testing
```

------------------------------------------------------------------------

## 21. First Build Session

Start with **Milestone 1 only**.

Create:

``` text
ai-access-gateway/
|
|-- gateway/
|   |-- app.py
|   |-- config.py
|   `-- proxy/
|       `-- origin_proxy.py
|
|-- test-agents/
|   |-- requests_test.py
|   `-- playwright_test.py
|
|-- .env
|-- .env.example
|-- requirements.txt
`-- README.md
```

First target:

``` text
Browser / Playwright / requests
             |
             v
      localhost:8000
             |
             v
        Python gateway
             |
        +----+----+
        |         |
      BLOCK      ALLOW
       403         |
                   v
             Stupidometer
```

Do not add AI detection in the first implementation.

First prove:

1.  Python is actually in the middle.
2.  It can proxy the origin correctly.
3.  It can prevent the origin response from reaching the client.
4.  Our `requests` and Playwright tests can distinguish `200` from
    `403`.
5.  Logs show exactly why the gateway made each decision.

Once these five tests pass, begin Milestone 2.

------------------------------------------------------------------------

## 22. Guiding Principles

1.  **Never send protected content and try to hide it afterward.**
2.  **Assume attackers understand our implementation.**
3.  **Do not depend on a fixed puzzle or secret frontend trick.**
4.  **Do not trust client-side claims.**
5.  **Do not classify from one browser property.**
6.  **Protect APIs as well as HTML.**
7.  **Protect the origin from direct bypass.**
8.  **Every defense gets an adversarial test.**
9.  **Every discovered bypass becomes a regression test.**
10. **Measure false positives as seriously as missed automation.**
11. **Keep challenge/session state short-lived and replay-resistant.**
12. **Build the gateway first; build the dashboard second.**

## 23. Immediate Next Step

Begin **Milestone 1: Python Gateway Foundation**.

The first implementation will be a small Python HTTP service on
`localhost:8000` that can either return an empty `403` or proxy a
request to the configured test origin. Once that is running, use the
existing `requests` and Playwright clients to attack/test it before
adding any challenge logic.

## Implementation status ? 2026-09-18

Milestones 1?3 implemented and verified with the automated test suite. See README.md
for the browser flow and current development limitations. The nonce challenge
is intentionally automatable; detection and production hardening are later milestones.
