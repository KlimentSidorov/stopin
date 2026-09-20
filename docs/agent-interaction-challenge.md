# Milestone 9: Agent Interaction Challenge

This document records the Milestone 9 baseline and its historical measurements.
[Milestone 10](adaptive-agent-experiments.md) extends the tripwire into three
experiment families and adds `experiment_exposed`, `experiment_activated`, and
`experiment_replay` events for newly issued challenges. The baseline results
below are retained for comparison.

## Hypothesis and scope

An autonomous browser exploring a verification protocol may fetch a resource
that a person following the visible flow never needs. This experiment measures
that interaction and its ordering. **Trap activation does not prove AI or even
malicious automation.**

This extends the existing per-session tripwire and signal groups. It does not
change the gateway architecture, origin guard, SaaS integration, dashboard UI,
or visible verification page. The browser experiment is a deterministic,
bounded resource-exploring Playwright agent, not an LLM-backed agent or a
representative sample of autonomous systems.

## Resource and normal flow

`POST /challenge` already creates a random server-side session and challenge.
Its `tripwire_url` points to a cryptographically random, 32-byte-token resource
under `/challenge/tripwire/`. Each new challenge has a different resource.

- The trap expires 300 seconds after issuance, independently of the evidence
  record's 600-second retention. Verification and replay never extend it.
- Access requires the matching HttpOnly challenge cookie, or a valid signed,
  unrevoked access session after verification. A different session, missing
  credentials, unknown ID, or expired resource receives an empty 404.
- The first bound GET returns an empty 204 and records activation. Subsequent
  bound GETs before expiry return an empty 410 and record replay.
- Non-GET requests return an empty 405 without activating the trap. The whole
  trap path namespace is reserved, including missing IDs and nested paths.
  It never proxies to the origin, even for an authorized session.
- Responses use `Cache-Control: no-store`. The trap never issues access cookies,
  returns a verification nonce, or contains protected HTML/API data.

The existing Continue handler ignores the URL and submits the challenge through
the normal verifier. There are no new hidden controls, links, focus stops,
prefetches, timing requirements, or visual puzzles. Keyboard Tab/Enter and the
existing live status region remain intact. JavaScript remains required, as it
was before this milestone.

The resource is intentionally discoverable in protocol JSON. It does not rely
on its purpose remaining secret, and an informed client can simply ignore it.

## Server evidence and policy

Per-session events contain an incrementing `order`, an event name, and elapsed
milliseconds measured by the server. Events include:

```text
challenge_issued
trap_activated / trap_replay              (only if requested)
verification_submitted
challenge_consumed
session_issued / verification_denied
protected_page_requested / protected_api_requested
```

Invalid verification attempts record `verification_rejected`. Protected-request
events mean the request was evaluated, not that content was granted. Consult
the associated ALLOW/CHALLENGE/BLOCK decision for the outcome.

The last 64 events are retained with a truncation flag and their original order
numbers. Activation phase is retained separately as `before_verification` or
`after_verification_started`, so truncation does not lose that evidence.
Replay counts saturate at 100. In-memory trap consumption uses a lock; Redis
uses the existing optimistic transaction mechanism across workers. The Redis
record's TTL is preserved on updates. Elapsed times are diagnostic; ordering
uses the counter, not timing thresholds. Redis workers use wall-clock deadlines
for the trap and should have synchronized clocks.

Trap OBSERVE events use the canonical path `/challenge/tripwire`, without the
random URL token. Policy events include the sequence in `signals.behavior` and
trap phase/replay in `signals.tripwires`. Existing structured logs and the
optional SQLite event bridge record these fields without dashboard changes.
No raw nonce, access cookie, browser string, or protected response body is added
to these records.

New explanatory reason codes are `trap_before_verification`,
`trap_after_verification_started`, and `trap_replay`. They accompany
`tripwire_activation`; they are **not additional independent risk groups**.
Even repeated trap activation plus its sequence cannot alone block an otherwise
valid verification/session. Existing combinations still apply:

- Trap plus reported WebDriver: multiple signal groups; verification is denied.
- Trap plus a server-observed request burst: combined evidence blocks access.
- Trap alone, including replay: verification may succeed and access may be allowed.

An ALLOW verification event's sequence includes `session_issued`; a denied
verification includes `verification_denied`. The verifier's `session.valid`
signal indicates eligibility from a consumed challenge, not proof that an
access session was ultimately issued. Use the decision, ordered outcome event,
and access-cookie observation together when interpreting the experiment.

## Adversarial browser experiment

`test-agents/exploratory_playwright.py`:

1. Loads the verification page and checks HTML/API access before verification.
2. Inspects DOM resource references.
3. Selects a visible form submission control without hardcoding its label.
4. Inspects outgoing JSON and recursively explores URL-like values before
   allowing the submission to continue. It does not hardcode the trap URL/key.
5. Limits exploration to 12 unique same-origin URLs, with no redirects.
6. Records resource statuses, session-cookie issuance, and protected HTML/API
   accessibility. The pytest harness joins these observations to server-side
   trap activations, policy reason codes, and ordered events.

A second variant removes the optional browser report. This deliberately tests
a bypass rather than assuming that clients honestly disclose WebDriver.
The verification endpoint and protected test routes are known to the harness;
this is not a general-purpose agent that learns arbitrary protocols.

## Observed local results (2026-09-20)

| Browser strategy | Trap activated | Access session issued | Protected HTML | Protected API |
| --- | --- | --- | --- | --- |
| Keyboard Tab/Enter control | No | Yes | Accessible after verification | Accessible after verification |
| Ordinary Playwright Continue control | No | Yes | Accessible after verification | Accessible after verification |
| Resource explorer, normal browser report | Yes | No | Inaccessible | Inaccessible |
| Resource explorer, browser report omitted | Yes | Yes | Accessible after verification | Accessible after verification |

Controls returned `browser_automation_hint`, `valid_verified_session` at
verification. Both controls use Chromium automation; the keyboard case tests
human-style interaction and is not a real-human measurement.

The reporting explorer returned `tripwire_activation`,
`trap_before_verification`, `browser_automation_hint`, `multiple_signal_groups`.
Its sequence was issuance, activation, verification submission, challenge
consumption, then verification denial. No origin requests occurred.

The report-omitting explorer returned `tripwire_activation`,
`trap_before_verification`, `valid_verified_session`. Its sequence ended in
session issuance instead. Both explorers had no initial HTML/API access, and
none of their explored resources contained protected content.

Full gateway suite: **98 passed, 1 skipped, 2 dependency deprecation warnings**.
The skipped test requires `TEST_REDIS_URL`. Real Chromium and the existing
production-built local Next.js origin tests ran. New unit tests exercise both
in-memory storage and fakeredis, including atomic concurrent activation,
cross-worker ordering, cross-site isolation, expiry, wrong-session access,
replay, and reserved-path content isolation. The real-Redis integration test
has matching activation/ordering coverage but was not executed locally.
Existing dashboard suite: **3 passed**.

Run from `StopIn`:

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -ra
# Print sanitized observations and policy reason codes for the browser experiment:
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider tests/adversarial/test_agent_exploration.py -s
```

Each explorer test also writes `agent-interaction-result.json` to its pytest
temporary directory. For a separately running authorized test gateway with
`/private` and `/api/private` endpoints, the browser probe can run independently:

```powershell
.\.venv\Scripts\python.exe test-agents/exploratory_playwright.py --url http://127.0.0.1:8000 --marker "Protected origin content"
.\.venv\Scripts\python.exe test-agents/exploratory_playwright.py --url http://127.0.0.1:8000 --marker "Protected origin content" --omit-browser-report
```

Standalone output contains browser observations. Policy reason codes and
activation ordering must be read from gateway logs or the event inspector;
there is no public endpoint exposing private server evidence.

## False positives, bypasses, and next measurements

- A debugger, extension, security scanner, accessibility-related tool, or curious
  person may explore JSON resources. Their activation is not evidence of AI
  identity. Multiple correlated tools can also produce multiple signal groups.
- The passing keyboard checks cover the existing simple page. They do not
  establish compatibility with all screen readers, extensions, or input devices.
- An agent can ignore the resource, omit/spoof optional browser observations,
  obtain a new challenge/session, or keep requests below burst thresholds. The
  report-omission bypass and ordinary Playwright success are demonstrated here.
- Evidence is scoped to the current server-generated session. A new challenge
  replaces the browser's binding and starts fresh evidence. This milestone does
  not introduce cross-session identity, fingerprints, or reset detection.
- In-memory evidence can be evicted or lost on restart. Redis persists evidence
  across workers until expiry. An unavailable/expired record means the trap
  cannot contribute evidence; it does not itself authorize origin access.
- Copied valid bearer cookies remain reusable within existing expiry/revocation
  limits. A trap cannot prevent extraction after an allowed session is issued.
- The explorer is one explicit resource-following strategy. Activation rates for
  real autonomous agents, false-positive rates for humans, and detection accuracy
  remain unmeasured. This result supports an instrumentation experiment, not a
  claim of reliable bot or AI detection.

Further evaluation should compare multiple agent strategies and real accessible
human workflows, with separately reported activation, issuance, denial, and
content-access outcomes. No production accuracy claim is made by Milestone 9.
