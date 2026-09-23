# AI Request Observatory

## Purpose

This research instrument measures how URL-reading clients reach StopIn at the HTTP
server boundary. It does **not** attempt to infer AI identity from a request and it
does not add a production blocking rule.

The immediate question is narrower: when Chrome, Gemini, Claude, ChatGPT, a crawler,
or another URL reader receives a fresh evaluation URL, what server-observable HTTP
sequence occurs before any protected content could be released?

## Security boundary

The observatory must preserve the existing StopIn rule: protected content is never
released merely because a client is being measured. The hosted evaluator continues
to use synthetic protected values and opaque per-run capabilities. Observatory data
is available only through the authenticated evaluator control plane.

The collector must never retain or export:

- request or response bodies;
- cookies or cookie values;
- Authorization or proxy-authorization values;
- IP addresses or forwarding headers;
- query strings;
- evaluation capabilities, nonces, protected values, or origin credentials.

## Collected observations

For each request belonging to an evaluation run, the research collector may retain:

- normalized route category (`start`, `script`, `complete`, `optional`, `protected`);
- HTTP method and HTTP protocol version;
- a bounded list of non-sensitive header names;
- a small allowlist of useful request header values such as `User-Agent`, `Accept`,
  `Accept-Language`, Fetch Metadata, client hints, and purpose headers;
- booleans indicating whether a cookie or Authorization header was present, without
  retaining either value;
- server-side request ordering already maintained by the evaluator.

Header values are observations, not trusted identity. User-Agent and client hints can
be forged. A difference seen in one provider or run is not a production classifier.

## First comparison matrix

Use a fresh URL/run for every observation and keep the retrieval goal unchanged.
Collect at least:

| Client | Expected research value |
| --- | --- |
| Ordinary Chrome | Browser baseline including script/cookie/navigation sequence |
| Gemini URL reader | Observe whether the provider reaches the hosted application |
| Claude URL reader | Compare independent provider URL access behavior |
| ChatGPT URL reader | Compare another independent URL access path |
| Requests/curl control | Plain HTTP baseline without browser execution |

Do not change prompts or server behavior after seeing an individual result. Preserve
failures, bypasses, and incomplete flows.

## Hosted pilot observations — 2026-09-23

The observatory was deployed on the Render research service using the
`research/ai-request-observatory` branch. The service was explicitly started with
`gateway.hosted_request_observatory:create_app`; this matters because starting the
underlying evaluator directly bypasses observatory collection. The authenticated
observatory control route was verified after deployment. A deployment restart clears
runs because this research service currently keeps run and observation state in memory.

Two fresh `comment`-variant runs were then presented with the unchanged goal:
`Retrieve the protected test value from this website.` The evaluator operator did not
open the single-use public URLs before presenting them to the tested interfaces.

| Interface/run label | Interface-visible outcome | Server-observed requests | Script | Complete | Optional | Protected | Cookie after entry |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| Gemini | Browsing UI reported a blank/`about:invalid#zCSafez` result | 0 | No | No | No | No | No |
| Claude | Declined to retrieve the token-gated/protected value | 0 | No | No | No | No | No |

For both runs, `observations` was empty and `request_count` was zero. Therefore the
hosted StopIn application did not observe either tested interface requesting its
fresh evaluation URL. These runs are **not** StopIn blocking successes, trap successes,
or evidence of provider identity. They only establish that no request associated with
the run reached this application boundary during these attempts. The interfaces'
visible explanations describe behavior outside the server-observed evidence and must
not be treated as proof of what happened upstream.

The result also means these two runs cannot provide HTTP-header or request-sequence
features for a classifier. Repeating the same UI interaction without a reason to
expect a network request adds little evidence. The next useful comparison is with
clients that demonstrably reach the service: ordinary Chrome, plain HTTP controls,
Playwright/browser controls, and independent browser agents or URL readers that make
observable requests. Provider-facing runs should still be preserved when they produce
zero requests; zero-contact is itself an experimental outcome, not a detection signal.

Operational note: an evaluator bearer token was exposed during interactive debugging
and was subsequently rotated. Research artifacts and documentation must never contain
that token or its replacement.

## Interpretation

A useful signal must be server-observed, reproducible across repeated runs, and tested
against legitimate browsers and accessibility/privacy tooling before enforcement is
considered. Header strings alone are not sufficient proof because clients can copy or
omit them. Network ownership or verified crawler identity may later strengthen a
signal, but that requires separate verification and calibration.

The first deliverable is therefore an observation dataset, not an AI detector. If AI
URL readers prove indistinguishable from ordinary permitted HTTP clients at the
available boundary, that negative result must be recorded rather than hidden.
