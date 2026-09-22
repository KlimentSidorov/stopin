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

### Milestone 1 --- Gateway foundation [DONE]

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

### Milestone 2 --- Session security [DONE]

``` text
[x] Challenge store
[x] Cryptographic nonce
[x] Expiration
[x] One-time consumption
[x] Signed access token/session
[x] Replay tests
```

### Milestone 3 --- Challenge client [DONE]

``` text
[x] Minimal challenge page
[x] Challenge submission endpoint
[x] Server verification
[x] Session issuance
[x] Protected navigation
```

### Milestone 4 --- Attack it [DONE]

``` text
[x] requests_test.py implemented
[x] playwright_test.py implemented
[x] Network interception test implemented (navigation, fetch, XHR)
[x] Challenge automation test implemented
[x] Replay test implemented
[x] Run Requests client with the requests dependency
[x] Run Chromium challenge automation and network interception tests
```

Code: `test-agents/` and `tests/adversarial/`. Verified on 2026-09-18 against
isolated local gateway/origin servers using Requests and real Chromium.
Full suite: **35 passed, 0 skipped**, with two dependency deprecation warnings.
Browser checks cover challenge automation, DOM, navigation, fetch, and XHR bodies.
See README.md for install/run commands.

### Milestone 5 --- Detection engine [DONE]

``` text
[x] Signal schema
[x] Request signals
[x] Browser/session signals
[x] Behavior signals
[x] Tripwire prototype
[x] Reason codes
[x] ALLOW / CHALLENGE / BLOCK evaluator
```

Verified on 2026-09-18: **48 passed, 0 skipped**, including real Chromium.
Signal collection and policy evaluation are separate. Tests cover single-signal
false positives, combined evidence, session issuance, tripwire session binding,
server-side activation logs, keyboard navigation, and evidence expiry/capacity.
No single signal identifies a visitor as AI. See README.md for prototype thresholds
and limitations; broad accessibility and real-traffic calibration remain future work.

### Milestone 6 --- Origin security [DONE - LOCAL NEXT.JS INTEGRATION]

``` text
[x] Prevent direct origin access
[x] Protect HTML
[x] Protect API
[x] Test origin bypass
```

Verified on 2026-09-18: **66 passed, 0 skipped**, including a production-built
local Next.js origin behind the FastAPI gateway and real Chromium. Direct HTML,
API, public-file, and generated Next.js asset access is denied. The origin guard
rejects forged/duplicate credentials and gateway session cookies. Verified gateway
requests succeed, and origin credentials are stripped before application code.

Scope: local integration completed. The real production site and its hosting/network
configuration were not changed. Production rollout and origin-firewall verification
remain pending. See `docs/origin-security.md` for local setup and deployment requirements.

### Milestone 7 --- Dashboard [DONE - LOCAL INTEGRATION]

``` text
[x] Site configuration
[x] Traffic overview
[x] Decisions
[x] Reason codes
[x] Policy configuration
```

Implemented in `../Stopin-Dashboard` with Next.js, Tailwind CSS, and a local SQLite
database via the libSQL client. The Python gateway optionally reads saved site
origins and policies and persists real decision events to the shared database.
Includes event filtering/inspection, UTC traffic charts, strictness, route rules,
and integration instructions. Verified on 2026-09-19: **70 gateway tests passed**,
**3 dashboard data tests passed**, production build and real Chromium checks.
Browser checks cover persisted forms, actual gateway policy enforcement, event
filters/inspection, empty states, and mobile navigation. This is a local operator
console; remote gateway transport, authentication, and tenant isolation are future work.

### Milestone 8 --- Production hardening [IMPLEMENTED - HOSTED VALIDATION PENDING]

``` text
[x] Redis/distributed session state (sessions, atomic challenges, evidence)
[x] Database (persistent SQLite, schema bootstrap, backup and retention commands)
[x] Metrics (authenticated, Redis-shared Prometheus request totals)
[x] Rate limiting (shared issuance/request limits and actual body-byte limits)
[x] Key rotation (active signer plus bounded previous-key verification)
[x] Multi-tenant isolation (site-bound gateway deployments and Redis namespaces)
[x] Deployment automation (Docker packaging, Railway config and CI workflow)
[x] Security testing (local suite; real Redis/container checks configured in CI)
[ ] Execute hosted CI/container/real-Redis validation and staging rollout
[ ] Public dashboard authentication and tenant authorization (local console remains private)
```

This is a single-operator starting deployment, not a public multi-tenant dashboard.
One gateway service uses two workers, Redis and a persistent SQLite volume.
Remote database/dashboard transport is still required for replicas or live remote
dashboard management. See `docs/production.md` for operating instructions and
the remaining hosting, restore and load-test checks. No paid service or real
origin deployment has been created by this implementation.

------------------------------------------------------------------------

### Milestone 9 --- Agent Interaction Challenge [DONE - LOCAL EXPERIMENT]

``` text
[x] Extend the existing unique per-session tripwire with a 300-second lifetime
[x] Preserve the accessible visible verification path; it never fetches the trap
[x] Record server-side activation, replay and bounded event ordering
[x] Feed trap phase and sequence reason codes into the existing signal/policy engine
[x] Keep activation/replay/sequence in one signal group; no single-trap classification
[x] Reserve the trap namespace; never proxy or return protected HTML/API content
[x] Test keyboard navigation and ordinary Playwright without trap activation
[x] Test activation, expiry, replay, wrong-session access and HTML/API isolation
[x] Test atomic in-memory and Redis-backed activation and cross-worker ordering
[x] Add a resource-exploring Playwright agent and a browser-report-omission variant
[x] Record trap activation, session issuance, policy reasons and content accessibility
[x] Document false positives, bypasses and the limits of this experiment
[x] Run the full existing gateway suite and dashboard tests after implementation
```

Verified on 2026-09-20: **98 gateway tests passed, 1 skipped**, with two existing
dependency deprecation warnings; **3 dashboard tests passed**. Real Chromium and
the existing local Next.js origin tests ran. The real-Redis integration test is
the sole skip because `TEST_REDIS_URL` is unset; new Redis-backed unit tests ran
with fakeredis. Real-Redis trap atomicity and ordering checks are included in the
opt-in integration test but remain unverified against a real Redis server locally.

Observed outcomes:

| Strategy | Trap | Session issued | Protected HTML/API |
| --- | --- | --- | --- |
| Keyboard human-style navigation | No | Yes | Accessible after verification |
| Ordinary Playwright | No | Yes | Accessible after verification |
| Resource-exploring Playwright, normal report | Yes | No | Inaccessible |
| Resource-exploring Playwright, report omitted | Yes | Yes | Accessible after verification |

The reporting explorer was denied with `tripwire_activation`,
`trap_before_verification`, `browser_automation_hint`, `multiple_signal_groups`.
The report-omitting explorer was allowed with `tripwire_activation`,
`trap_before_verification`, `valid_verified_session`. Trap sequence and replay
do not count as extra independent signal groups. The report-omission result is
a documented bypass, not a detection success.

This is a bounded, deterministic resource-exploration agent, not an LLM-backed
agent evaluation. Keyboard controls are automated interaction checks, not a
real-human study. No AI identity, detection accuracy, or false-positive rate is
established. Gateway/SaaS architecture, origin protection and dashboard UI were
not redesigned. See [experiment protocol, results and limitations](docs/agent-interaction-challenge.md).

------------------------------------------------------------------------

### Milestone 10 --- Adaptive Agent Interaction Experiments [IMPLEMENTED AND MEASURED LOCALLY]

``` text
[x] Reuse challenge/session/tripwire/evidence and Redis abstractions
[x] Add AgentExperiment records with random IDs, scoped binding, expiry and replay
[x] Support resource, protocol-action and metadata-reference families
[x] Randomize identifiers and descriptor exposure order; retain a normal accessible path
[x] Record server-observed exposure, activation and sequence independently of browser claims
[x] Preserve server evidence when telemetry is omitted or spoofed
[x] Keep correlated experiments in one signal group; do not add arbitrary block thresholds
[x] Add reusable normal, resource, protocol, no-telemetry and StopIn-aware browser strategies
[x] Measure each strategy against three fresh randomized challenges
[x] Add keyboard, mouse, slow, repeated-navigation and refresh/back controls
[x] Verify isolation, expiry, replay, session binding, randomness, secret hygiene and atomicity
[x] Save actual per-run activation/order/report/decision/reason/session/HTML/API results
[x] Document false positives, presentation bias and observed bypasses
[x] Run the complete gateway suite, all real Chromium adversarial tests and dashboard tests
```

Verified on 2026-09-20: **145 gateway tests passed, 1 skipped**, with two existing
dependency deprecation warnings; **3 dashboard tests passed**. Real Chromium and
the existing local Next.js origin tests ran. Real Redis is the sole skip because
`TEST_REDIS_URL` was unset; fakeredis tests cover all three families, and the
opt-in real-Redis test now includes their cross-worker activation/replay checks.

Measured results (three independent contexts/challenges per strategy):

| Strategy | Activated families | Report supplied? | Verification | Session | HTML | API |
| --- | --- | --- | --- | --- | --- | --- |
| Normal visible Playwright | None | Yes | ALLOW | Yes | Yes | Yes |
| Resource explorer | Resource, metadata | Yes | BLOCK | No | No | No |
| Protocol explorer | All three | Yes | BLOCK | No | No | No |
| Telemetry-omitting explorer | All three | No | ALLOW | Yes | Yes | Yes |
| StopIn-aware adversary | None (three deliberately ignored) | No | ALLOW | Yes | Yes | Yes |

All five human-style controls activated no experiments and obtained access after
verification. These are automated controls, not human false-positive-rate studies.
All pre-authorization HTML/API probes and experiment responses lacked protected
content. Denied explorers never reached the origin.

**Recorded bypasses:** the aware adversary succeeded in 3/3 runs by ignoring all
optional resources, and the telemetry-omitting explorer succeeded in 3/3 runs
despite all three observed activations. Reporting explorers still depended on
the inherited WebDriver hint for their second signal group. No policy was added
to hide these outcomes. Test success is not detection success; reliable AI
detection and real-world false-positive rates remain unestablished.

See [architecture, complete matrix with activation order and exact reason codes,
limitations and research questions](docs/adaptive-agent-experiments.md) and the
[actual 20-run JSON artifact](docs/adaptive-agent-results.json). The agents are
deterministic exploration strategies, not LLM-backed agents. Existing gateway,
origin guard, dashboard and production-hardening architecture was retained.

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

Research direction correction: Milestone 12 investigates optional exploratory actions
**before application delivery**. Do not proceed with mouse movement, reaction timing,
scrolling or behavioral-human classification. The active research result and limits
are documented in [Pre-Application Agent Trap Research](docs/pre-application-agent-trap.md).
Production rollout work below remains separate; this experiment changes no production policy.

Milestones 1-7 are complete locally, Milestone 8 gateway hardening is implemented,
and Milestones 9-10 are implemented and measured as local agent interaction experiments.
Next: execute CI and verify the Railway staging deployment, Redis behavior,
backup restoration and expected load. Milestone 6 production rollout remains
separate and requires origin protection in the actual hosting environment.

## Implementation status - 2026-09-19

Milestones 1-7 implemented locally and verified with the automated test suite. See README.md
for the browser flow and `docs/production.md` for Milestone 8 deployment boundaries.
The nonce challenge is intentionally automatable; hardening does not establish humanity.

## Milestone completion tracker

| Milestone | Status |
| --- | --- |
| 1 - Gateway foundation | DONE |
| 2 - Session security | DONE |
| 3 - Challenge client | DONE |
| 4 - Attack it | DONE |
| 5 - Detection engine | DONE |
| 6 - Origin security | DONE - local Next.js integration; production rollout pending |
| 7 - Dashboard | DONE - local Next.js/Tailwind dashboard and SQLite gateway integration |
| 8 - Production hardening | Gateway implementation complete; hosted validation and public dashboard authorization pending |
| 9 - Agent Interaction Challenge | DONE - local experiment; 98 passed, 1 real-Redis test skipped; bypass and false-positive limitations documented |
| 10 - Adaptive Agent Interaction Experiments | IMPLEMENTED AND MEASURED LOCALLY - 145 passed, 1 real-Redis test skipped; aware-adversary and telemetry-omission bypasses recorded |
| 11 - Human vs Automation Measurement | Measurement implementation available; 15 automation samples collected. DETECTION RESEARCH INCOMPLETE — 9 completed operator-confirmed manual Chrome samples (protected requests 503); Firefox/mobile pending |
| 12 - Pre-Application Agent Trap Research | IMPLEMENTED AND MEASURED LOCALLY - 72 strategy runs, 3 manual Chrome runs and 3 matched Playwright Chrome runs; identical ordinary action traces, minimum-protocol and late-exploration bypasses documented; production policy unchanged |

Milestone 4 explicitly documents that automation can solve the current challenge
and copied valid bearer cookies remain usable. These are current design limitations,
not evidence of human verification or replay-resistant access cookies.

## Milestone 11 — Human vs Automation Measurement

Development-only, explicitly enabled loopback runner supports repeated manual
verification runs, post-completion `manual-human` metadata and sanitized JSON
exports. Server-observed evidence is separate from untrusted client/operator
claims. The existing five Playwright strategies use the same recorder. No access
rules, experiments, human-speed thresholds or AI probabilities were added.

See [measurement procedure and analysis](docs/human-vs-automation-measurement.md)
and [sanitized cohort artifact](docs/human-vs-automation-results.json).
Implementation tests validate measurement plumbing only. Nine completed manual Chrome
samples were confirmed by the operator; protected content requests failed with 503.
The corrected batch and descriptive overlap analysis are linked from the measurement
guide. Matched end-to-end runs and Firefox/mobile cohorts remain pending; detection
research is not complete.
Validation: complete suite 154 passed, 1 real-Redis integration test skipped
(`TEST_REDIS_URL` not configured).

### Milestone 11 successful manual cohort update

Three distinct completed manual Chrome runs now have post-run human labels with
operator confirmation provenance, successful verification, and protected page/API
HTTP 200 responses. See `docs/human-vs-automation-successful-comparison.json`.
Original exports and prior origin-failure observations are preserved separately.
Timing, experiment non-activation and session behavior overlap automation.
Firefox/mobile and broader matched sampling remain pending; detection research
is still incomplete.

## Milestone 12 — Pre-Application Agent Trap Research

Research question: can an autonomous explorer interpreting a StopIn-only bootstrap
be induced to perform an observable action unnecessary for ordinary browser execution,
before the protected application is delivered or executed?

Implemented a separate loopback lab gateway with three randomized, session-bound,
90-second bootstrap variants: comment recovery index, inert JSON index, dormant
JavaScript helper. The ordinary bootstrap executes automatically without user input.
Only an explicit lab authorization permits an origin request; HTML, API, application
data and assets remain unavailable before that boundary. No production imports,
policy changes, behavioral classification, webdriver checks or fingerprint rules.

Observed results: all 27 early explorers following optional information were blocked
with zero origin calls/content; nine non-completing HTML parsers also received none.
Normal Playwright, the aware adversary and a no-JavaScript minimum-protocol client
each obtained the protected app in 9/9 runs. Nine late explorers received HTML before
trap activation. Fresh-session retry is another tested bypass. Three operator-confirmed
manual Chrome runs matched three Playwright Chrome action traces across all variants.
The instrument cannot distinguish identical browser execution or invisible analysis.

Full validation: 166 Python tests passed, one real-Redis integration skipped because
`TEST_REDIS_URL` is unset; all browser and real Next.js tests passed. Dashboard tests:
3 passed. See [methods, observations, limitations and artifacts](docs/pre-application-agent-trap.md).
These controlled scripted strategies establish conditional optional-action detection,
not reliable induction of arbitrary agents or human-vs-automation classification.
