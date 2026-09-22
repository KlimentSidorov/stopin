# Milestone 11 — Human vs Automation Measurement

Measurement implementation is available. **Detection research is incomplete: no
reliable human/automation distinction has been established. Five successful labeled manual Chrome runs are now recorded; earlier exploratory runs with origin failures remain separately documented.** Passing tests prove
the measurement system works; they do not prove humans and automation can be
distinguished. No new access rules, experiments, speed thresholds, AI probabilities,
or webdriver-based conclusions are introduced.

## Run manually on your own browser

Follow [local setup](local-setup.md) to start the protected demo origin. For a
comparable baseline use its gateway setup with the following settings, in the
gateway PowerShell terminal before launching it:

```powershell
$env:GATEWAY_ENV = 'development'
$env:GATEWAY_MEASUREMENT_ENABLED = 'true'
$env:GATEWAY_DEV_ACCESS_TOKEN = ''
$env:GATEWAY_TRUST_RAILWAY_PROXY = 'false'
$env:GATEWAY_ALLOWED_HOSTS = '127.0.0.1,localhost'
$env:GATEWAY_DASHBOARD_DB = ''
.\.venv\Scripts\python.exe -m uvicorn gateway.app:create_app --factory --workers 1 --host 127.0.0.1 --port 8000
```

Retain the matching origin secret and signing secret from local setup. Use one
worker, no reload, and the same hostname throughout. Empty dashboard configuration
selects the existing balanced policy without route overrides; it does not modify
the dashboard. Measurement also works with a configured dashboard, but record its
policy separately when comparing results.

1. Open `http://127.0.0.1:8000/__measurement` in your actual Chrome browser.
2. Select `manual_chrome`, then **Start fresh run**. This clears only the browser's
   gateway authentication/challenge cookies. It creates no access session.
3. Open the verification-flow link and manually click **Continue**. Do not use
   Playwright or scripts to operate the browser. The runner does not automate it.
4. Visit the protected API using the runner's link. Return to the protected page,
   refresh it, visit the API, and use Back. Keep the runner tab open.
5. Return to the runner, **Finish current run**, then **Label completed run
   manual-human**. Finish denied/failed attempts too, so they are not silently
   excluded. Labeling is an operator assertion, not independently verified identity.
6. Download the JSON export before restarting the server. Repeat from step 2 for
   fresh runs. Keep only one run active per browser profile; tabs share its cookie.
7. Repeat in actual Firefox using `manual_firefox` if installed. Record browser
   versions, device, keyboard/mouse use and deviations in your research notes.

For fair comparisons, repeat the automation baseline's actions as well: open the
protected page, visit the API before verification in a second tab, return and
Continue, then visit both protected page and API. Keep additional refresh/back
runs separate in your notes. Automation's API requests are fetches; manually
opening the API is navigation, which is a known protocol difference, not identity.

The default collector produces three runs per strategy. Three manual repetitions
per browser would match that small pilot, **not establish statistical sufficiency**.
Include slower devices, privacy settings and keyboard operation in later cohorts.

Actual mobile samples remain pending. A mobile device must have a private tunnel
or USB forwarding to the loopback listener (using a loopback URL on the device).
Do not expose the listener on a LAN or disable its peer/Host checks. Mobile
emulation in Playwright is automation and must not be labeled manual mobile.
If a safe forwarding setup is impractical, leave this cohort pending.

## Collect the existing automation strategies

Against that same explicitly enabled local server:

```powershell
.\.venv\Scripts\python.exe test-agents/measurement_playwright.py --url http://127.0.0.1:8000 --marker "Protected origin content" --repetitions 3 --output docs/human-vs-automation-results.json
```

The collector uses the existing M10 `BrowserExperiment` strategies unchanged and
fresh browser contexts. It waits 15 seconds **between** runs to respect existing
rate limits; this delay is outside measured runs. Avoid concurrent traffic, and
wait for the rate window to clear if 429 occurs. It fails on setup/finish errors
rather than inventing a successful sample. Export includes any manual runs already
stored on that server. Running the collector overwrites the selected output file;
use different filenames to retain separate batches.

## Recorded evidence and its limits

`SERVER_OBSERVED` contains request arrival/completion order, monotonic elapsed
times, method, status, route category, parsed optional telemetry presence, existing
challenge/experiment lifecycle events, access decisions and session continuity.
Session numbers are run-local ordinals, never session IDs. Run cookies are never
exported. Paths are reduced to fixed categories; no query strings or protected
URLs, response bodies, headers, IP addresses, tokens, nonces, experiment resource
IDs, browser reports or private evidence blobs are copied to artifacts.

Existing evidence sequences are ingested at decision/experiment log points and
deduplicated by internal session and lifecycle order. Their `challenge_elapsed_ms`
is the original server measurement; outer `elapsed_ms` is recorder ingestion
time. Request ordinals represent arrival order; completion order may differ under
concurrency. Events never become inputs to the policy evaluator.

`CLIENT_REPORTED_UNTRUSTED` explicitly records that report values are not retained.
Seeing an optional browser field is a server observation; its contents would remain
untrusted claims. Cohort selection and `manual-human` are separate untrusted
operator metadata. Neither `human=true` nor labels grant authorization.

Challenge issuance happens after clicking Continue in the current flow, so the
verification duration excludes the person's time reading the page. Request timing
also cannot identify time spent thinking or navigating cached history. Repeated
route categories cannot conclusively distinguish refresh from fetch or navigation.
Absence of an observed request is not evidence that the browser performed no action.

Storage is bounded to 200 worker-local runs, two hours per run and 2,000 events per
run. Restart loses data; export first. Incomplete or truncated runs remain visible
in raw results but are excluded from feature cohort counts. Missing manual labels
are excluded from human observations. The gateway's existing evidence retention
also applies; a very long run can outlive challenge/session evidence. Do not merge
counts from different exports of the same live dataset as independent samples.

## Original automation pilot artifact (before manual collection)

[human-vs-automation-results.json](human-vs-automation-results.json) contains 15
actual Playwright Chromium runs against an isolated protected test origin, plus
explicit pending entries for all three manual cohorts. The test fixture used a
1,000 requests/minute budget to run quickly; balanced access policy and experiments
were unchanged. The CLI uses the configured server limits with pacing instead.
These deterministic strategies are not LLM agents. Timing values depend on this
machine and workload and must not be used as classification thresholds.

| Cohort | Samples | Challenge-to-submission ms (all samples) | Requests/run | Sessions issued |
| --- | ---: | --- | --- | ---: |
| A. Manual Chrome | 0 — pending | Pending | Pending | Pending |
| B. Manual Firefox | 0 — pending | Pending | Pending | Pending |
| C. Manual mobile | 0 — pending | Pending | Pending | Pending |
| D. Normal visible-flow Playwright | 3 | 11, 8, 8 | 8 | 3/3 |
| E. Resource explorer | 3 | 21, 20, 25 | 11 | 0/3 |
| F. Protocol explorer | 3 | 22, 29, 20 | 11 | 0/3 |
| G. Telemetry-omitting explorer | 3 | 21, 23, 20 | 12 | 3/3 |
| H. StopIn-aware adversary | 3 | 10, 11, 11 | 8 | 3/3 |

| Feature | Human observations | Automation observations | Overlap | Sample size | Possible false positives / limits |
| --- | --- | --- | --- | --- | --- |
| Verification duration distribution | Pending | 8–29 ms; raw values and min/median/max in JSON | Unknown without humans | H=0, A=15 | Network, device load, accessibility; pre-click delay excluded |
| Request/event ordering | Pending | Issuance/exposure precede submission and consumption; explorers activate existing experiments before submission | Unknown | H=0, A=15 | Concurrency and retries reorder requests; ingestion order differs from lifecycle time |
| Navigation transitions | Pending | Page/API category sequences retained, including denied pre-verification requests | Unknown | H=0, A=15 | API navigation differs from fetch; back/forward cache hides transitions |
| Challenge retries | Pending | One issuance and submission per baseline run; retry plumbing separately unit-tested | Unknown | H=0, A=15 | Expiry, disconnects and accidental clicks can cause retries |
| Refresh behavior | Pending | No deliberate refresh in this pilot; repeated categories are retained | Not measured conclusively | H=0, A=15 baseline, 0 dedicated refresh samples | Repeated requests do not identify refresh; use dedicated manual/control runs |
| Request bursts | Pending | Per-run interarrival intervals and request counts retained | Unknown | H=0, A=15 | Parallel tabs, assets and network batching create legitimate bursts |
| Experiment interaction | Pending | Resource explorer activates resource/metadata; protocol and telemetry-omitting explorers activate all three; visible/aware flows activate none | Unknown | H=0, A=15 | Extensions may explore; informed automation ignores experiments |
| Session continuity | Pending | Visible, telemetry-omitting and aware flows receive sessions and make subsequent validated requests | Unknown | H=0, A=15 | Privacy tools, cookie restrictions, expiration and fresh contexts |
| Optional telemetry | Pending | Present in D/E/F; absent in G/H | Unknown | H=0, A=15 | Optional data can be suppressed or forged |

Each feature also has machine-readable observations, sample sizes, overlap status
and false-positive concerns in the artifact and live exports. Raw durations and
interarrival intervals permit later distribution analysis without a speed rule.
No false-positive rate or AI probability can be estimated from this pilot.

## Confirmed manual Chrome batch ? 2026-09-21

The operator confirmed that every run in `human-vs-automation-results (1).json`
was performed manually in Chrome while changing dropdown options. Those options
only named cohorts; they did not launch automation or change browsers. The original
export is preserved unchanged and must not be interpreted as an automation batch.

[Corrected manual artifact](human-vs-automation-manual-chrome-corrected.json) records
that confirmation and each original cohort/run ordinal. Only completed runs receive
post-run `manual-human` metadata; all server-observed events remain unchanged.
There are **9 completed manual Chrome runs and 4 unfinished records** (three empty,
one with successful verification). Firefox and mobile remain pending.

[Updated comparison](human-vs-automation-comparison.json) combines these nine
completed manual runs with the original 15 automation runs. Do not add the original
misclassified export as another batch: that would duplicate these observations.

All ten manual attempts that submitted verification received sessions, including
the unfinished attempt. Subsequent protected requests returned **503**, despite
ALLOW decisions. This is a content-delivery/configuration failure, not evidence of
bot classification or a successful end-to-end visit. The earlier empty origin
secret is consistent with this failure, but the artifact alone does not establish
the exact server configuration. These runs cannot measure normal protected browsing.

| Feature | Human observations (9 completed Chrome runs) | Comparison / overlap with 15 automation runs | Limitations |
| --- | --- | --- | --- |
| Verification duration | 10, 5, 9, 8, 8, 6, 8, 8, 8 ms; median 8 ms | Automation 8?29 ms; ranges overlap at 8?10 ms | Measures the protocol after the click, not human reading/reaction time; different batches |
| Request/event ordering | Issue, expose, submit, consume, issue session | Same core sequence as successful automation | Concurrent/omitted observations and different workflows limit comparisons |
| Navigation transitions | Recorded page/API requests; protected responses 503 | Both cohorts request page/API categories | Broken origin prevents normal navigation comparison |
| Challenge retries | One issuance/submission per completed run | Also one per automation baseline run | Does not cover expiry/retry behavior |
| Refresh behavior | Repeated categories in some runs | No conclusive refresh identification in either batch | Could be navigation, retry or refresh |
| Request bursts | 4?7 requests/run; raw interarrival intervals retained | Automation 8?12 requests/run under scripted workflow | Different actions and failed content loads; not an identity signal |
| Experiment interaction | No activations | Also none for visible-flow and aware automation | No activation is not proof of humanity |
| Session continuity | Sessions issued and validated on subsequent protected requests | Also seen in allowed automation | ALLOW does not imply content was delivered; manual requests ended in 503 |
| Optional telemetry | Present in all completed manual submissions | Also present for visible-flow, resource and protocol automation | Presence is shared and contents are untrusted |

This is one operator's self-reported Chrome batch, not nine independent people.
Browser version and matched environment are not established. No false-positive
rate, AI probability, or detection-completion claim follows from these observations.

## Successful manual Chrome cohort - updated with results (5)

The included successful cohort now contains **five distinct completed manual Chrome
runs**: one from results (2), two from results (3), and two from results (5).
The two new runs in [results (5)](human-vs-automation-results%20%285%29.json) already
have the `manual-human` label; no label correction was needed. Their server event
records do not duplicate the earlier included samples. The unlabeled completed
run in results (3) retains the operator-confirmation provenance described in the
corrected artifact. Original exports are unchanged.

| Results (5) run | Cohort | Completed | Label | Verification | Protected page | Protected API | Protocol duration |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | manual_chrome | Yes | manual-human | ALLOW / 200 | ALLOW / 200 | ALLOW / 200 | 10 ms |
| 2 | manual_chrome | Yes | manual-human | ALLOW / 200 | ALLOW / 200 | ALLOW / 200 | 6 ms |

[Successful manual samples](human-vs-automation-manual-chrome-successful.json)
and [successful-flow comparison](human-vs-automation-successful-comparison.json)
now include these five manual runs against the original 15 automation samples.
All five issued sessions and recorded ALLOW plus HTTP 200 for protected page and
API. Manual durations are 12, 10, 9, 10 and 6 ms (median 10 ms), overlapping the
automation range of 8-29 ms. These measure the post-click protocol, not reaction
time. No manual experiment activations occurred; visible-flow and aware automation
also avoid them. Telemetry presence and session continuity likewise overlap allowed
automation behavior. Per-feature observations, sample sizes and concerns are in
the updated JSON comparison.

Earlier exploratory batches remain separately preserved, including origin 503
failures. Those failures are not included as successful samples. These five runs
are from one operator, not five independent people. Firefox/mobile remain pending,
and collection conditions are not matched. **Detection research remains incomplete.**

## Security and validation

The namespace `/__measurement` is reserved and returns 404 when disabled. It is
registered only when explicitly enabled in development. Production settings reject
measurement, as do development access-bypass and trusted-proxy configurations.
Requests must originate from a loopback peer with a loopback Host. Mutation
requests require the exact same Origin. Pages and exports use no-store and a
restrictive CSP. There is no LAN/public debug access or origin bypass.

Exports are accessible to local processes/users of the explicitly enabled listener;
this is a single-operator research tool, not a multi-user service. Ordinary
production clients receive no measurement endpoint. Existing gateway cookie
filtering keeps the measurement cookie out of origin requests. Turn the feature
off and restart when finished.

Tests cover real browser cohort collection, lifecycle capture, telemetry omission,
retries, labels, secret/body sanitization, expiry/capacity, disabled mode, remote
peers, Host/Origin checks and forbidden configurations. Existing adversarial tests
remain the regression checks for origin protection and access behavior.

Final full-suite validation: **154 passed, 1 skipped**. The real-Redis integration
test was skipped because `TEST_REDIS_URL` was not configured. Two existing
Starlette dependency deprecation warnings remain. Browser tests required execution
outside the Windows sandbox because it denied Playwright subprocess pipes.

**Milestone 11 detection research remains incomplete. Manual Chrome samples now
exist, but matched end-to-end runs and broader cohort analysis are still needed.** Even then, overlapping behavior may support no useful
distinction. Any future policy change requires separate evidence and review.
