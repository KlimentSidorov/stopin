# Milestone 8: production hardening

Implemented for one operator and one site per gateway deployment. The public
gateway has Redis security state, persistent SQLite configuration/events,
request metrics, rate limits, signing-key overlap, deployment packaging and
security tests. This does not make the local dashboard a public SaaS console.

## Hosting and cost

Railway Hobby is the suggested starting point for low operational effort. As
checked on 2026-09-19, it has a $5 monthly minimum including $5 of usage. A
**$5–15/month planning estimate** for a lightly used gateway and Redis is not a
quote or cap; memory, CPU, storage and gateway egress determine the bill. Origin
hosting and domain registration are separate. Review usage after the first day
and week. See [pricing](https://railway.com/pricing).

Keep one gateway service with two workers, one Redis service and a persistent
gateway volume. SQLite supports workers on one host, not geographically
distributed replicas. Railway volumes prevent service replicas and cause brief
redeploy downtime. A remote database adapter and dashboard transport are needed
before scaling beyond this topology. See [volume limitations](https://docs.railway.com/volumes/reference).

## Railway setup

1. Deploy this repository using the included Dockerfile and `railway.json`.
   If deploying a parent monorepo, set the service root to `StopIn` and set the
   config-file path to `/StopIn/railway.json` in Railway settings.
2. Add a Redis service on the private project network, with persistence and
   authentication. Set `maxmemory-policy noeviction` and a memory limit suitable
   for the service. Use AOF persistence; `appendfsync always` avoids the one-second
   acknowledged-write loss window of `everysec`. Redis failures must deny access.
   Never expose the Redis TCP port publicly. See
   [Redis persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/).
3. Attach a persistent volume at `/data` to the gateway. Set
   `RAILWAY_RUN_UID=0` to prepare the initially root-owned volume. The entrypoint
   changes only `/data` ownership, then drops to UID/GID 10001 before opening
   the database or accepting requests. Existing files must be owned by that UID.
4. Generate an HTTPS service domain and configure the variables below. Generate
   each secret independently with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
5. Configure the existing origin guard with the origin secret and enforce origin
   network restrictions from [origin-security.md](origin-security.md). This task
   has not modified or deployed the real protected website.
6. Disable service sleeping. Deploy and check `/ready`, HTTPS cookies, challenge
   completion and direct-origin rejection. Verify that a client-supplied
   `X-Real-IP` is overwritten by the Railway edge before routing real traffic.

| Variable | Value |
| --- | --- |
| `GATEWAY_ENV` | `production` |
| `GATEWAY_SITE_ID` | Your stable site ID; letters, digits, `_` or `-` |
| `GATEWAY_DOMAIN` | Your gateway hostname, without a scheme |
| `GATEWAY_ALLOWED_HOSTS` | Gateway hostname plus `healthcheck.railway.app`, comma-separated |
| `GATEWAY_ORIGIN_URL` | Protected origin URL |
| `GATEWAY_ORIGIN_SECRET` | Independent random secret shared with the origin |
| `GATEWAY_TOKEN_SECRET` | Independent random signing key, at least 32 characters |
| `GATEWAY_METRICS_TOKEN` | Independent random metrics key, at least 32 characters |
| `GATEWAY_REDIS_URL` | Reference the Redis service's private authenticated `REDIS_URL` |
| `GATEWAY_DASHBOARD_DB` | `/data/stopin.db` |
| `GATEWAY_COOKIE_SECURE` | `true` |
| `GATEWAY_DEV_ACCESS_TOKEN` | Empty |
| `GATEWAY_TRUST_RAILWAY_PROXY` | `true` only behind Railway HTTP ingress |
| `RAILWAY_RUN_UID` | `0`; entrypoint drops privileges before serving |
| `WEB_CONCURRENCY` | `2` |

The container uses Railway's `PORT`. Database bootstrap is idempotent and does
not overwrite existing site configuration. Origin or policy changes to an existing
deployment must update the saved database, not only its environment variables.
Railway's healthcheck hostname is documented
[here](https://docs.railway.com/deployments/healthchecks).

## Security state and tenant boundaries

Challenge consumption is a single Redis Lua operation. Wrong-browser attempts
cannot consume another browser's challenge; a bound attempt consumes it even
with a wrong nonce. Challenges and sessions have 300-second TTLs, evidence 600
seconds. Evidence updates use optimistic transactions so separate workers do
not overwrite tripwire hits. Redis outages return 503; there is no memory fallback.
Lua atomicity is documented by [Redis](https://redis.io/docs/latest/develop/programmability/).

Each deployment has one configured site, an explicit host allowlist and its own
keys and database. Redis state is namespaced by site; tokens and session lookups
check the site. Request headers cannot choose a site or origin. Namespaces protect
against accidental cross-site application access, not someone holding unrestricted
Redis credentials: use separate Redis services or site-scoped Redis ACLs for
mutually untrusted deployments. Do not grant tenants database or Redis access.

The dashboard remains a trusted local operator tool. With a remote gateway,
download a consistent database backup for local inspection; it is a snapshot,
not live synchronization. Editing the local copy does not update the hosted site.
Public dashboard login, user roles and tenant authorization are still outstanding.

## Limits, metrics and failures

Defaults are 120 requests/minute per peer and 20 challenge issuances/minute per
peer, shared across workers, with 429 and `Retry-After`. Tune via
`GATEWAY_RATE_LIMIT` and `GATEWAY_CHALLENGE_RATE_LIMIT`. IP identities are HMACed
before storage. Buckets expire after 60 seconds. These are fixed windows, not
a volumetric DDoS defense. Token-key rotation also resets the rate identities.

Forwarding headers are ignored by default. Railway mode uses its `X-Real-IP`
header and rejects a missing or invalid IP; enable it only behind the Railway
HTTP edge with all private project peers trusted. Direct TCP ingress is unsafe
in this mode. See [Railway headers](https://docs.railway.com/networking/public-networking/specs-and-limits).

Request bodies are limited to 1 MiB, or 16 KiB for challenge verification, counting
actual streamed bytes. The entrypoint limits worker concurrency to 100.
`/health` reports process liveness; `/ready` checks Redis and site configuration.
`/metrics` requires `Authorization: Bearer <metrics key>` and exposes shared
Prometheus request totals by site and HTTP status class. Paths, IPs and session
IDs are not metric labels. Scrape over HTTPS and monitor 429/5xx plus Redis
memory and disk use. Railway deployment healthchecks are not continuous monitoring.

## Signing-key rotation

1. Generate a new independent random key.
2. Before changing the active key, add the new key to every worker's
   `GATEWAY_TOKEN_PREVIOUS_SECRETS` JSON list so all workers can verify both keys.
3. Switch `GATEWAY_TOKEN_SECRET` to the new key and put the old key in the previous
   list. New tokens use the new key; both keys verify during the overlap.
4. Wait at least 300 seconds after the last old-key issuer stops, then remove the
   old key. At most two previous keys are accepted.

For compromise, remove the affected key immediately instead of allowing overlap;
existing cookies signed by that key then fail. Session revocation in Redis is
immediate across workers. Origin-secret rotation is separate: coordinate with
the origin guard, which currently accepts a single secret.

## Database maintenance

Run maintenance in the gateway container as UID 10001. Bootstrap uses WAL and
an idempotent schema migration. Configuration reads and event writes on async
request paths run in the thread pool. Event-write failure is logged; invalid or
unavailable site configuration denies requests. Event storage is best-effort,
not a lossless audit log.

```sh
python -m gateway.database backup --db /data/stopin.db --destination /data/backup-2026-09-19.db
python -m gateway.database prune --db /data/stopin.db --site YOUR_SITE --days 30
```

Schedule pruning daily using your operator scheduler. Copy backups off the
gateway volume and test restoration to a separate instance. A backup on the
same disk is not disaster recovery. Restore the SQLite backup while workers are
stopped; preserve UID 10001 ownership. Redis state and SQLite backups have
separate lifecycles. A lost Redis store revokes sessions and requires verification.

## Verification and remaining rollout work

Local verification on 2026-09-19: **82 passed, 1 skipped**, with two existing
dependency deprecation warnings. The skip is the real-Redis integration test.
`pip-audit -r requirements.lock` reported **no known vulnerabilities**.

The local suite covers browser/origin regressions, cross-worker challenge
completion and revocation, parallel consumption, tenant boundaries, Redis outage,
body limits, metrics auth, proxy handling, key rotation and backup/retention.
Redis unit tests use fakeredis with Lua support. `TEST_REDIS_URL` opts into a
separate real-Redis integration test that uses and cleans only a random namespace.

The included CI workflow runs a real Redis service, browser tests, dependency
audit and Docker build. Those hosted checks have not been executed from this
workspace. Before marking the production rollout complete: run CI, deploy to a
staging domain, test proxy-header overwrite and volume permissions, restore a
backup, load-test the expected traffic, and verify origin isolation in hosting.
