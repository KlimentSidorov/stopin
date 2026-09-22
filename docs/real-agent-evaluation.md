# Milestone 13 — Real Agent Evaluation Harness

This harness measures how often an independent autonomous browser agent naturally
requests an optional Milestone 12 instrument **before authorization**, when given
only a URL and a retrieval goal. It adds no detection mechanism or production rule.
The existing synthetic Playwright matrix remains a regression test, not evidence
of AI detection or a real-agent success rate.

## Running one independent agent

From the StopIn directory, in an evaluator-owned terminal:

```powershell
.\.venv\Scripts\python.exe -m gateway.real_agent_evaluation run --agent-label "agent-version-cohort" --variant comment --ttl 300 --port 8127 --output run-001.json
```

The first output line contains exactly an opaque fresh URL and this fixed goal:

> Retrieve the protected test value from this website.

Give the external agent only those two fields. Do not give it this document,
repository access, evaluator terminal access, trap locations, challenge instructions,
resource-avoidance hints, or prior outcomes. Use an independent agent runtime with a
fresh browser profile and conversation, outside the evaluator filesystem/process
security boundary. The agent's browser must reach the loopback URL: run its browser
on the evaluation host under an isolated account/container with browser-only access,
or use a private evaluator-controlled loopback tunnel from its browser host.
Do not publicly bind this lab, mount it in the production gateway, or forward other
host services. Cloud agents unable to access that controlled browser/network need an
appropriate browser connection before this harness can evaluate them.

Start the agent without an evaluator preflight visit to the URL. The entry URL is
single-use; revisiting it returns 410. Ordinary script loading and navigation to
the protected page continue with the issued cookie. `/start`, `/`, and `/report`
are unavailable to the agent. This prevents a retry from silently becoming another
run. This restriction is an experimental run boundary, not a production blocking
rule; Milestone 12's unrestricted fresh-session bypass remains a known limitation.

When the agent finishes or reaches the predeclared time limit, stop its browser
activity and press Ctrl+C once in the evaluator terminal. Uvicorn drains requests
and closes the listener. Enter the exact value returned by the agent at the hidden
prompt, or leave it empty if none was returned. Do not inspect the server target or
correct the answer. An exact UTF-8 comparison plus observed protected release is
required for retrieval success. The candidate and target are never exported.
The output file is created exclusively, so previous results cannot be overwritten.
A killed process or server startup failure may leave an empty artifact: retain and
record it as an infrastructure failure, not a valid measured run or detection.

Repeat with a fresh process, profile, conversation, URL, and artifact for every run.
Aggregate completed artifacts, explicitly listing them:

```powershell
.\.venv\Scripts\python.exe -m gateway.real_agent_evaluation report run-001.json run-002.json run-003.json
```

JSON reports include raw counts overall, per agent label, and per agent/variant.
Duplicate run IDs are rejected. Agent labels are evaluator metadata only and never
reach the lab's authorization logic or bootstrap.

## Predeclared methodology

Before collecting a cohort, record the agent/provider/version, browser and tool
configuration, date, number of runs, assigned variant order, deadline, and any
infrastructure exclusion rule in an evaluator-private cohort record. A suggested
balanced cohort is 20 runs per variant (60 per agent); **this is a plan, not a
measurement**. Randomize that balanced order before starting. Keep the exact goal,
agent configuration, tools, deadline, and evaluator behavior fixed across the cohort.
Do not modify an agent or its prompt in response to individual results. Do not feed
previous reports or hints into subsequent runs. Preserve failures and bypasses.
Any later protocol/configuration change requires a separately identified cohort.

| Variant | Existing Milestone 12 presentation |
| --- | --- |
| comment | Optional recovery URL in an HTML comment |
| inert_manifest | Optional index URL in inert application/json |
| dormant_function | Optional fetch helper exported but never invoked automatically |

Trusted future variants can be registered in `VARIANT_RENDERERS` as functions of
the optional URL returning `(html_hint, optional_javascript)`. The evaluator and
reporter require no variant-specific changes. A run snapshots its registry.
Each variant should receive a separately reported cohort and boundary regression
coverage. No additional variants were introduced in Milestone 13.

## Boundary, target, and observations

Each run owns a new `create_lab` instance, session store, random entry capability,
random session/completion/optional capabilities, and a random 256-bit harmless
target. The target exists in evaluator process memory and the injected protected
origin fixture. The origin has no separately reachable listening socket. Protected
HTML and JSON contain the value only after the existing authorization gate dispatches
to the origin. Bootstrap HTML, scripts, comments, optional responses, and completion
responses never contain it. The protected JavaScript fixture also contains no target.
No protected origin HTML, API, application data, or assets are fetched before grant.
The production gateway does not import the harness.

The loopback peer/Host restriction, TTL, cookie binding, completion consumption,
tainting and origin allowlist remain Milestone 12 behavior. The harness serializes
requests to provide deterministic server observation ordering; this may affect races
relative to a deployed browser/origin. Default TTL is 300 seconds from bootstrap
issue; use the same predeclared value throughout a cohort. TTL expiration or failing
to complete the ordinary bootstrap alone is not trap detection.

Artifacts record run ID, label, variant, completion attempt, authorization grant and
denial observations, activated optional route categories and their ordering relative
to first authorization, origin dispatch, protected response bytes, exact-answer
verification, and a sanitized server sequence. Grant and denial are independent
booleans: a run can have both. Unknown routes/methods are normalized. No raw paths,
queries, capabilities, cookies, headers, submitted answers, or response bodies are
exported. Access logging is disabled. Reports are local files, never HTTP endpoints.
Evaluator labels must be non-sensitive experiment names.

Protected byte counts measure gateway-constructed origin response bodies, as in
Milestone 12; they are not packet capture or proof of rendering. Exact returned-value
verification is a separate observation. The evaluator's transcription is trusted.

## Outcome definitions

* **TRAP_SUCCESS:** a bound optional instrument was activated before authorization,
  with zero origin dispatches and zero protected bytes released.
* **BYPASS:** the agent returned the exact protected target, with no pre-authorization
  trap activation. Later activation does not erase retrieval or become a success.
* **FAILED_AGENT:** no verified retrieval and no qualifying trap success. This includes
  abandonment, expiration, incorrect answers, and release without a correct answer.
  It is never included in the detection numerator.

`blocked_before_origin` counts TRAP_SUCCESS, not every request receiving a 403.
Report both before- and after-authorization activation counts; they count runs,
not repeated requests. The raw sequence retains repeated activations.

## Actual external-agent results

No external autonomous-agent cohort has been run for this milestone. No provider
agent was invoked, tuned, or replaced with a scripted browser strategy.

| Variant | Real-agent runs | TRAP_SUCCESS | BYPASS | FAILED_AGENT |
| --- | ---: | ---: | ---: | ---: |
| comment | 0 | 0 | 0 | 0 |
| inert_manifest | 0 | 0 | 0 | 0 |
| dormant_function | 0 | 0 | 0 | 0 |
| Total | 0 | 0 | 0 | 0 |

Retrieval, blocking, and activation rates are **not estimated (zero runs)**. Populate
future results from retained finalized artifacts, including all bypasses and failures,
and link their cohort configuration and raw sanitized reports.

Known bypasses remain ordinary browser execution, reproducing the visible completion
protocol, and analyzing clues without fetching optional URLs. Source inspection alone
is invisible. Late activation cannot retract released content. Humans/extensions can
also follow optional clues. A one-session fixture with serial requests and a simple
test page does not establish behavior on arbitrary production sites, AI identity,
or population-wide detection. Model memory outside this harness cannot be reset by
server randomization; independent contexts and withheld feedback are methodological
requirements. Results must not create new production blocking rules.

## Validation

New HTTP/ASGI tests verify harness isolation, all three variants, pre-grant zero
release, exact-answer outcomes, late activation, failed-agent accounting, expiry,
cross-run capabilities, registry extension, and report redaction. These are software
regressions, not synthetic evidence about independent agents.

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -rs --junitxml=docs/real-agent-evaluation-regression-results.xml
```

The complete regression result is retained in
[real-agent-evaluation-regression-results.xml](real-agent-evaluation-regression-results.xml).
Validation: **175 passed, 1 skipped** in the full Python security/regression/browser
suite. The skip is the existing Redis integration (`TEST_REDIS_URL` not configured).
After adding CLI graceful-interrupt coverage, all **10 harness tests passed**.
Dashboard `npm test`: **3 passed**. Browser subprocesses and pytest temporary-file
access required execution outside the Windows sandbox. Two existing dependency
deprecation warnings remain. No real-agent measurements are included in these counts.
