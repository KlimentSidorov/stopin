# Milestone 12 — Pre-Application Agent Trap Research

## Result

The instrument detects **following optional bootstrap information**, not automation
or humanity. Normal Playwright and a StopIn-aware adversary bypass it by executing
the ordinary bootstrap. A client can also reproduce the completion request without
executing JavaScript. Parsing, compiling, executing, or silently analyzing JavaScript
does not itself produce an exploration signal.

Three operator-confirmed manual Chrome runs and three Playwright-controlled installed
Chrome runs against the **same lab process** had identical normalized action traces
for all three variants, including response status and body byte counts. The instrument
cannot distinguish those human-operated and automated executions. Random capabilities,
absolute timestamps and global sequence offsets are excluded from comparison; this is
not a claim of identical timing, HTTP headers, TLS traffic, or every possible browser
observable. None of those are used as classification rules.

Production policy, production routes and prior research implementations are unchanged.
No mouse, scrolling, human timing, webdriver, fingerprint, human-behavior classifier,
challenge button or human puzzle was added. Milestone 12 supersedes behavioral
classification as the active research direction; previous artifacts remain historical.

## Isolation and release boundary

`gateway/pre_application.py` is a separate FastAPI factory, never imported or installed
by `gateway.app`. It accepts only loopback peers and loopback Host names. Run one worker.
The normal production gateway does not acquire a new lab authorization bypass.

1. `GET /start` (or `/`) returns minimal StopIn-owned HTML and issues a random,
   HttpOnly, SameSite=Strict session cookie. The response contains a title, an inert
   optional clue and a bootstrap script URL. It contains **zero origin content**.
2. `GET /__trap/script/<capability>` returns only StopIn JavaScript. The script
   automatically posts to `/__trap/complete/<capability>` and navigates to `/private`
   on success. It requires no input from the person using the browser.
3. Completion explicitly grants this **lab session** access if it is unexpired,
   unconsumed and has not followed a bound optional route. This grant is a test
   instrument, not evidence of a human and not a production access credential.
4. Only after that grant may the lab call its injected origin client. The allowlist
   comprises protected HTML, API, application data and a JavaScript asset fixture.
   All other routes fail closed. Unauthenticated direct HTML/API/asset requests
   receive empty 403 responses; they do not contact the origin.

Sessions expire after 90 seconds, including authorization. Script/completion
capabilities and optional-route capabilities are independent random 192-bit values,
bound to the server-issued cookie. Capability substitution, cross-session use,
completion replay, expiration and forged authorization headers are tested. Replay
does not revoke a previously valid grant. Responses use `no-store`, a restrictive CSP
and `nosniff`. No origin secret, origin URL, Next.js payload, protected API result,
HTML or asset is embedded in the bootstrap. The optional routes always return an
empty 403 and never proxy, even for an authorized session.

Origin credentials, when needed for the real Next.js test, belong to the injected
server-side HTTP client. Incoming cookies, authorization headers and origin-secret
headers are not forwarded. The fixture gateway does not forward upstream redirects
or Set-Cookie headers. It is intentionally not a general-purpose production proxy.
The demo uses a synthetic origin containing only `LAB-PROTECTED-FIXTURE /private`.
No live protected application or deployment was modified.

## Experimental variants

Default assignment randomly selects a variant. Tests explicitly select each variant
for balanced coverage; session and route capabilities remain freshly randomized.

| Variant | Optional information | Extra action an explorer may choose |
| --- | --- | --- |
| `comment` | HTML comment naming an optional application recovery index | Request the URL in the comment |
| `inert_manifest` | Non-executable `application/json` script containing an optional application index | Parse the JSON and request the named URL |
| `dormant_function` | JavaScript exports an optional recovery function but never calls it | Interpret its body and request its URL, or invoke the helper |

None of these URLs is a resource automatically fetched by HTML parsing or required
by the normal script. Merely reading the comment, parsing the JSON, or examining
the function without making a request is invisible to this instrument. Randomizing
the capabilities prevents blind reuse, not semantic recognition of the trap.

## Evidence semantics

| Action or field | Server observed? | Cause and trust boundary |
| --- | --- | --- |
| Bootstrap/script GET, completion POST, protected navigation GET | Yes: method, normalized route, order, timestamp, response status and constructed body size | Automatically caused by the ordinary script/browser; equally reproducible by automation |
| Optional capability request | Yes, checked against the session | Unnecessary for normal execution; caused by the tested explorer choosing to follow optional information. Does not prove AI, maliciousness, or human absence |
| Authorization and origin dispatch | Yes, server-side state transitions | Origin dispatch is recorded only after a valid lab grant |
| `protected_bytes` | Yes, constructed gateway response bytes from the injected origin | Zero before authorization; not a network capture or proof of client rendering |
| JavaScript parsing, compilation, source reading, reasoning, DOM inspection | No | No report is accepted for these; silent interpretation cannot be detected |
| `normal_playwright`, `agent_like_solver`, other strategy labels | Harness metadata | Which strategy the test ran; not server-inferred identity |
| Manual Chrome label and success confirmation | Operator-reported | User confirmed all three runs; the server cannot verify who operated the browser |
| Browser/version label | Harness-reported | Useful collection context, not a security signal |

Research event exports retain global sequence order, monotonic timestamps and anonymous numeric run IDs.
They omit cookies, raw capabilities, query strings, credentials and protected bodies.
The entry request can refer to the preceding cookie's run; `issued` identifies the
new run. Comparison begins at that event and ends at the first protected response.
No client telemetry endpoint or spoofable client assertion drives lab authorization.
Loopback `/report` exports observations; do not expose this lab on a public service.
Ordinary HTTP client/access logs are separate and can contain capability paths;
the reproduction command disables Uvicorn access logging.

## Measured matrix

Collected 2026-09-22. Automated matrix: Chromium 153.0.8010.12, three repetitions
per strategy per variant, **72 runs**. Each automated run probes HTML, API, application
data and JavaScript asset access. These are controlled scripted strategy models;
no general-purpose LLM was queried and these counts are not population detection rates.

| Client | Runs | Optional route followed | Protected content released |
| --- | ---: | ---: | ---: |
| Manually operated ordinary Chrome | 3 | 0 | 3 |
| Playwright, installed Chrome, matched manual control | 3 | 0 | 3 |
| Ordinary Playwright Chromium | 9 | 0 | 9 |
| Requests/HTML parser, no JavaScript or protocol completion | 9 | 0 | 0 |
| Playwright resource explorer, before execution | 9 | 9 | 0 |
| Protocol/JavaScript explorer, before completion | 9 | 9 | 0 |
| Agent-like solver interpreting recovery/index clues | 9 | 9 | 0 |
| StopIn-aware adversary executing only normal bootstrap | 9 | 0 | 9 |
| No-JavaScript client reproducing minimum protocol | 9 | 0 | 9 |
| Resource explorer after ordinary bootstrap completion | 9 | 9 | 9 |

Early Playwright explorers deliberately pause/abort the automatic script while they
inspect its source and the bootstrap. The resource strategy extracts optional URLs;
the agent-like strategy interprets the recovery/index/helper hint as an application
retrieval route. The protocol explorer fetches the script and follows its optional
information before submitting completion. These model particular choices, not an
inevitable response to a trap. The late explorer obtains the optional capability from
the harness's session state to isolate ordering; it is a privileged test strategy.
A real explorer can extract the same capability from the bootstrap/script.

For all **27 early exploratory runs**, and all **9 non-completing parser runs**:
zero origin dispatches and zero protected response bytes. All four protected fixture
paths are denied. Separate tests repeat the boundary against an actual locally
running secured Next.js origin, checking HTML, API, RSC-shaped requests, data/asset
paths, secret non-disclosure and zero origin-client dispatch before authorization.
Normal fixtures test data and JS delivery after authorization; the Next.js extension
checks real HTML/API delivery. Existing Next.js security/browser tests also pass.

## Bypasses and limitations

* **Same browser execution:** human-operated Chrome and Playwright-controlled Chrome
  generated the same observed action trace in 3/3 matched variant comparisons.
  Installed Chrome under Playwright reported version 153.0.8010.48. The operator's
  Chrome version was not independently collected. The sample is small; no human
  classification claim follows from it.
* **Minimum protocol without JavaScript:** read the bootstrap/script, preserve the
  cookie, POST the visible completion capability. All nine runs obtained the app.
  Secret obfuscation in client-delivered code would not repair this distinction.
* **Analyze without following optional links:** source interpretation is invisible.
  Reading an optional hint does not require contacting its server endpoint.
* **Late exploration:** all nine late explorers received protected HTML before their
  optional request was observed. Subsequent access was revoked, but already released
  content cannot be retracted. Therefore “every exploratory client receives zero
  content” is **false**; zero release holds only for exploration observed before
  authorization. A protected response already in flight is likewise not retracted.
* **Fresh-session retry:** a client can abandon a tainted session, request a new
  bootstrap and follow the minimum path. The real Next.js tests demonstrate this
  bypass. There is no IP/device ban or cross-session identity assumption.
* **Shared cookies:** possession of the authorized cookie grants access until expiry;
  this experiment does not bind identity to a human or prevent credential copying.
* **False-positive possibility:** a human using source tools, an extension, a security
  scanner or a link-following tool could activate optional information. These
  populations were not measured. Optional-route activation is an action signal.

The narrow research question has a conditional positive result: an explorer that
chooses to follow the recovery/index clue makes an observable extra request. This
does **not** establish reliable induction of arbitrary autonomous agents, nor any
separation between a person and automation taking the same execution path.

## Reproduction and artifacts

From the StopIn directory:

```powershell
.\.venv\Scripts\python.exe -m uvicorn gateway.pre_application:create_demo_lab --factory --host 127.0.0.1 --port 8126 --no-access-log
```

Open `/start?variant=comment`, `/start?variant=inert_manifest` and
`/start?variant=dormant_function` in ordinary Chrome without DevTools. Each should
automatically reach the protected fixture. Save `/report` **before** running the
automated comparison, and record operator provenance separately. Then:

```powershell
.\.venv\Scripts\python.exe test-agents/pre_application_compare.py --manual docs/pre-application-manual-chrome.json --output docs/pre-application-chrome-comparison.json
.\.venv\Scripts\python.exe -m pytest tests/unit/test_pre_application.py tests/adversarial/test_pre_application_browser.py -p no:cacheprovider -s
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -rs
```

The matrix prints its sanitized JSON artifact path in pytest's temporary directory.
The comparison script runs installed Chrome through Playwright against the same lab.
Use fresh artifact paths for new cohorts to preserve the recorded evidence.

* [72-run automated matrix](pre-application-agent-trap-results.json)
* [Raw manual Chrome observations](pre-application-manual-chrome.json)
* [Matched Chrome comparison and operator provenance](pre-application-chrome-comparison.json)
* [Full gateway regression result](pre-application-regression-results.xml)

Validation: **166 passed, 1 skipped** in the complete Python regression/security/
browser suite, including the real Next.js integration. The sole skip is the real
Redis integration because `TEST_REDIS_URL` is not configured. Two existing dependency
deprecation warnings remain. Dashboard `npm test`: **3 passed**. Browser and Node
tests required execution outside the Windows sandbox because subprocess creation
was denied. No production deployment or policy change was performed.
