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
| Gemini URL reader | Observe the initial-fetch path seen in the September pilot |
| Claude URL reader | Compare independent provider URL access behavior |
| ChatGPT URL reader | Compare another independent URL access path |
| Requests/curl control | Plain HTTP baseline without browser execution |

Do not change prompts or server behavior after seeing an individual result. Preserve
failures, bypasses, and incomplete flows.

## Interpretation

A useful signal must be server-observed, reproducible across repeated runs, and tested
against legitimate browsers and accessibility/privacy tooling before enforcement is
considered. Header strings alone are not sufficient proof because clients can copy or
omit them. Network ownership or verified crawler identity may later strengthen a
signal, but that requires separate verification and calibration.

The first deliverable is therefore an observation dataset, not an AI detector. If AI
URL readers prove indistinguishable from ordinary permitted HTTP clients at the
available boundary, that negative result must be recorded rather than hidden.
