# Milestone 10: Adaptive Agent Interaction Experiments

## Finding

The additional instruments distinguish the tested exploration strategies, but
they do **not** establish reliable AI detection. In the measured local runs, a
StopIn-aware adversary ignored every optional resource and obtained protected
HTML and API content. A protocol explorer omitting optional browser telemetry
activated all three experiment families and also obtained access.

These are recorded bypasses. Passing pytest establishes implementation and
security invariants; it is not a detection-success criterion.

## Architecture

The existing gateway, challenge verifier, session stores, origin guard, Redis
transactions, dashboard, and production-hardening architecture are retained.

`gateway/challenges/experiments.py` introduces `ExperimentFamily` and
`AgentExperiment`. Each experiment stores:

- A cryptographically random `experiment_id` and independent random `resource_id`.
- The challenge ID and server-generated session ID to which it belongs.
- Family, allowed method, protocol presentation, creation time, and expiry.
- Activation state, first activation order/phase, and bounded replay count.

IDs use `secrets.token_urlsafe(32)` (32 random bytes). The factory supports one
to three distinct registered families. Current issuance selects **all three**
and cryptographically shuffles their exposure order. It does not adapt the
selection to browser fingerprints or make randomness a security boundary.
The three families are explicit implementations of a common framework, rather
than three independent ad hoc stores.

`EvidenceStore.expose_experiments()` attaches records to the existing session
evidence. The same records are serialized through `RedisEvidence`; its existing
WATCH/MULTI transactions preserve atomic activation and event ordering across
workers. In-memory updates reuse the existing lock. Redis key names, TTL model,
site isolation, and challenge/session authorization remain unchanged.

The existing `tripwire_url` is retained as an alias for the resource family's
endpoint. Old clients can still follow the legitimate verification protocol.
Previously stored evidence without experiment records retains its legacy trap
handling until expiry. Deploy matching worker versions together; mixed-version
schema compatibility has not been tested.

## Experiment families

| Family | Discovery surface | Activation | What it measures |
| --- | --- | --- | --- |
| `resource` | A URL-like protocol value; also the existing `tripwire_url` | GET `/challenge/tripwire/<random-id>` | Fetching a resource unnecessary for verification |
| `protocol_action` | An action descriptor with URL, `method: POST`, and an empty body | POST `/challenge/experiments/<random-id>` | Following a declared protocol action, beyond generic GET crawling |
| `metadata_reference` | An opaque `urn:stopin:notes:<random-id>` reference and its resolution URL | GET `/challenge/experiments/<random-id>` | Inspecting optional referenced metadata |

Descriptors appear in the challenge JSON's `experiments` array. They contain no
protected content, origin secret, access token, or challenge nonce. Experiment
responses are empty, including successful activations. The ordinary challenge
response still contains the nonce needed by the existing verifier; experiments
never return or echo it themselves.

The metadata resolver and resource are both GET-based instruments. A generic
URL walker may fetch both for the same underlying reason. Their activations
are correlated, not two independent proofs of automation. GET on the POST action
returns 405 and does not activate it. Wrong-method probes are not currently
retained as separate behavioral evidence.

The design is deliberately recognizable. An informed attacker can ignore all
three descriptors and the legacy URL. There are no secret frontend tricks.

## Normal verification path

The existing visible form requests a challenge, submits its nonce, receives a
session if authorized, and navigates to the protected destination. Its script
does not fetch experiment resources. There are no new hidden clickable elements,
focus targets, links, prefetches, puzzles, or minimum human-speed thresholds.
The native submit control and polite status live region remain unchanged.
JavaScript remains required, as in Milestone 9.

Passing the nonce protocol demonstrates possession of the challenge/session,
not humanity. An ALLOW decision means authorization under the current policy;
it is not an assertion that the visitor is trustworthy or human.

## Server-observed versus untrusted evidence

The server records an ordered sequence such as:

```text
1  challenge_issued
2  experiment_exposed       family varies with shuffled order
3  experiment_exposed
4  experiment_exposed
5  experiment_activated     only when requested with the bound credentials
... experiment_replay      only on a repeated valid activation
... verification_submitted
... challenge_consumed
... verification_denied OR session_issued
... protected_page_requested / protected_api_requested
```

Exposure means the server prepared the descriptor for its response. It does not
prove a client read it. A protected-request event means policy evaluation, not
that content was delivered; consult the access decision and observed response.

The counter is ordered by committed evidence updates, not inferred from browser
timing. The last 64 events are retained with a truncation flag. Each experiment
separately retains its first activation order and phase, even after event history
is truncated. Replay counts saturate at 100. Deadlines are 300 seconds from
issuance and are never extended by activation, verification, or replay; the
evidence record retains the existing 600-second TTL. Redis workers use absolute
wall-clock deadlines and should have synchronized clocks.

Server observations include family exposure, bound endpoint activation, request
method, replay, verification order, the presence/absence of a browser report,
session issuance, and protected-route requests. The actual values of
`javascript`, `webdriver`, and `elapsed_ms` are **client-reported and untrusted**.
Their absence does not clear experiment evidence, reset the server event sequence,
or whitelist a request. Tests verify that an existing server-observed burst plus
activation blocks with telemetry omitted, `webdriver: false`, or `webdriver: true`.

`signals.tripwires.experiments` contains sanitized family observations; the
ordered sequence is in `signals.behavior.interaction_sequence`. The server records
`browser_report_supplied` separately from the report's claims. Structured logs
and the existing optional SQLite event bridge receive these fields. Exposure
and activation are OBSERVE events; no dashboard redesign was needed.

Event paths are canonical `/challenge`, `/challenge/tripwire`, or
`/challenge/experiments`, without random resource IDs. Evidence snapshots contain
family names, order, phase, and counts, not resource URLs/IDs, experiment IDs,
nonces, access cookies, origin credentials, or protected bodies. Existing
server-side session correlation IDs remain in structured gateway events.
The published result artifact omits those session correlation IDs as well.

## Policy choice and its limits

Milestone 10 adds the explanatory reason `multiple_experiment_families`; it
does **not** add a new block threshold or count correlated family activations,
replay, and phase as independent groups. One accidental activation alone cannot
classify a person as AI. Several family activations alone also remain one
exploration group under the current conservative policy.

The inherited policy still combines this group with other evidence, including
the optional WebDriver report. Consequently, removing that report can change
the decision when no other signal group exists. **That reliance remains a
measured policy weakness.** Retaining suspicious server evidence is not the same
as having a calibrated rule that should block on it. No missing-report trust rule,
standalone WebDriver block, arbitrary fingerprint, or trap-count block was added
to make the experiment look effective.

## Reusable adversarial harness

`test-agents/adaptive_playwright.py` defines five strategies on a shared runner:

1. **Normal visible flow:** use the visible submit control and supply the normal
   browser report, without exploring optional protocol values.
2. **Resource explorer:** inspect DOM references and URL-like values in the
   challenge response; fetch discovered same-origin resources with GET.
3. **Protocol explorer:** inspect the challenge network response and follow
   declared GET/POST action/resource descriptors before verification.
4. **Telemetry-omitting explorer:** use the protocol explorer's behavior, but
   remove the optional browser report from verification.
5. **StopIn-aware adversary:** inspect the protocol, deliberately ignore its
   three optional experiments, and submit only challenge ID, session ID, and
   nonce. It also omits optional telemetry.

Each run has a fresh Chromium context and isolated gateway/origin fixtures.
Exploration is bounded to 12 unique `(method, URL)` pairs, restricted to the
same origin, with no redirects and a 10-second resource timeout. Explorers do
not hardcode trap identifiers or families to activate them. The aware strategy
intentionally knows the legitimate verification field names. The harness knows
the fixture's challenge endpoints and protected routes; it is not an arbitrary
website agent or an LLM-driven strategy.

The legacy `tripwire_url` occurs before the descriptors in the JSON. These
walkers therefore encounter the resource family first, despite shuffled
descriptor exposure. This presentation bias is recorded, not concealed.

## Measured results (2026-09-20)

The full-suite run produced [adaptive-agent-results.json](adaptive-agent-results.json),
containing all **15 strategy runs** (three per strategy) and **five control runs**.
It includes per-run sequence/timing, activation order, report presence,
verification decision/reasons, access-cookie issuance, and HTML/API accessibility.

In the table, R = `resource`, A = `protocol_action`, and M = `metadata_reference`.
Numbers after `@` are server event order numbers. All three runs of each
strategy had the same decision and access outcome.

| Strategy | Experiments activated | Activation order | Browser report? | Verification | Reason codes | Session issued? | HTML accessible? | API accessible? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Normal visible Playwright | None | None | Yes | ALLOW | `browser_automation_hint`, `valid_verified_session` | Yes | Yes | Yes |
| Resource explorer | R, M | R@5, M@6 (3/3) | Yes | BLOCK | `tripwire_activation`, `trap_before_verification`, `multiple_experiment_families`, `browser_automation_hint`, `multiple_signal_groups` | No | No | No |
| Protocol explorer | R, A, M | R@5, A@6, M@7 (3/3) | Yes | BLOCK | `tripwire_activation`, `trap_before_verification`, `multiple_experiment_families`, `browser_automation_hint`, `multiple_signal_groups` | No | No | No |
| Telemetry-omitting explorer | R, A, M | Run 1: R@5, M@6, A@7; runs 2-3: R@5, A@6, M@7 | No | ALLOW | `tripwire_activation`, `trap_before_verification`, `multiple_experiment_families`, `valid_verified_session` | Yes | Yes | Yes |
| StopIn-aware adversary | None | None | No | ALLOW | `valid_verified_session` | Yes | Yes | Yes |

All initial protected HTML/API probes were inaccessible. None of the explored
resources returned protected content. Denied explorers made no origin requests.
For allowed runs, content became accessible only after verification issued a
session. Each aware-adversary run recorded three deliberately ignored resources.

**Bypass 1:** the telemetry-omitting explorer obtained protected content despite
all three server-observed activations. **Bypass 2:** the aware adversary ignored
every instrument and obtained content. Ordinary visible-flow Playwright also
succeeds, as intended by this experiment's constraints. The two BLOCK rows are
not evidence of reliable AI detection: their decisions still depend partly on
an optional report that an attacker controls.

## False-positive controls and risks

| Control | Experiments activated | Session / HTML / API | Verification reason codes |
| --- | --- | --- | --- |
| Keyboard Tab/Enter | None | Yes / Yes / Yes | `browser_automation_hint`, `valid_verified_session` |
| Normal mouse click | None | Yes / Yes / Yes | `browser_automation_hint`, `valid_verified_session` |
| Slow interaction (1.2-second pause) | None | Yes / Yes / Yes | `browser_automation_hint`, `valid_verified_session` |
| Repeated navigation/reload | None | Yes / Yes / Yes | `browser_automation_hint`, `valid_verified_session` |
| Refresh/back before and after verification | None | Yes / Yes / Yes | `browser_automation_hint`, `valid_verified_session` |

These are automated human-style controls, not a human cohort. Each retains a
single visible submit button and polite live status. Keyboard focus reaches the
submit button. Navigation controls require only one verification, and no test
or policy assumes people must interact slowly.

Unit controls accidentally activate each family individually, replay it, and
verify successfully without optional browser reports. This confirms that one
family/replay alone does not cause classification or denial. It does not promise
zero false positives: a legitimate extension, scanner, developer tool, privacy
tool, or accessibility workflow could follow descriptors. Multiple tools could
also contribute other signal groups and cause an inherited policy denial.
Real screen readers, browser extensions, and real-human false-positive rates
remain unmeasured.

## Security invariants and test results

Every family is tested in memory and with fakeredis for:

- No protected HTML/API before authorization and no origin proxying from
  experiment endpoints, including malformed paths and unsupported methods.
- Wrong-session, missing-session, and cross-site rejection; expiring resources.
- First activation (empty 204), recorded/rejected replay (empty 410), and atomic
  concurrent consumption. Unknown/expired/wrong-session resources return 404;
  a wrong method on a known bound resource returns 405 without activation.
- Unpredictable ID construction, collision/format regression checks, and
  challenge/session binding. Sampling IDs is not a proof of randomness quality.
- No access session issued by an experiment, no response-body secret leakage,
  and sanitized logs. Endpoints never echo request bodies or credentials.
- Cross-worker ordering and preserved TTL, with matching real-Redis integration
  coverage available when `TEST_REDIS_URL` is supplied.

Complete gateway suite: **145 passed, 1 skipped, 2 existing dependency
deprecation warnings**. The sole skip is the real-Redis integration test because
`TEST_REDIS_URL` was unset. All real Chromium adversarial tests, including the
existing Next.js origin integration, ran. All **3 dashboard tests passed**.
This verifies local implementation, not hosted load behavior or detection accuracy.

From `StopIn`, reproduce the full suite and matrix:

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -ra
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider tests/adversarial/test_adaptive_browser.py -s
```

The matrix fixture writes `adaptive-agent-results.json` under pytest's temporary
`adaptive-results` directory and prints its path. The checked-in JSON is the
artifact copied from the full-suite run above. Random IDs, order, and timing
will vary on subsequent runs.

To run browser observations against your authorized local demo (start it using
[local setup](local-setup.md)):

```powershell
.\.venv\Scripts\python.exe test-agents/adaptive_playwright.py --url http://127.0.0.1:8000 --marker "Protected origin content" --strategy all
```

The standalone runner has no private server-evidence endpoint. Its JSON reports
browser observations; join gateway logs for activation/order/decision reasons.
The pytest harness performs that join using isolated captured server events.

## Remaining bypasses and research questions

An informed agent can ignore every experiment, omit or forge telemetry, create
a fresh challenge to reset session evidence, or stay below rate thresholds.
Copied bearer cookies remain reusable within existing expiry/revocation limits.
Content delivered to an allowed session can be extracted. Experiment secrecy,
resource-count thresholds, and browser fingerprints are not solutions established
by this work.

The next questions are empirical:

- How do different real agent implementations explore unfamiliar protocols,
  including ones explicitly warned about StopIn?
- Do metadata references and action descriptions produce measurably different
  behavior from ordinary URL following, after removing presentation-order bias?
- Which combinations of independently observed behavior justify enforcement
  without penalizing legitimate scanners, extensions, and accessible workflows?
- What are activation and false-positive rates for real humans, and how do they
  compare with these small deterministic control runs?
- Can an entirely server-observed policy improve outcomes after calibration,
  without depending on optional browser claims or counting correlated actions twice?

Milestone 10 establishes a reusable measurement framework and documents bypasses.
It does not establish an AI classifier or claim that every explorer should be blocked.
