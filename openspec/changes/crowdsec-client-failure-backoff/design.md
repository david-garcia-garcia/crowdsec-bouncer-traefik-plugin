## Context

See proposal.md — Why. On `master`, `lapi.Client.LiveLookup` and `appsec.Client.Query` always perform HTTP (`HTTPTimeoutSeconds`, default 10s) before `crowdsecLapiFailureAction` / `crowdsecAppsecFailureAction`. Stream/alone already skip per-request LAPI via `StreamHealthy` + `updateMaxFailure`. Sister implementation: traefik-modsecurity `pkg/health.Tracker` (tumbling window, trip, timed recover). Yaegi: copy the algorithm in-tree; do not import that module. Reclaim: constructor `ctx` is the holder; Tracker is a field on each Client, not a package global.

## Goals / Non-Goals

**Goals:**
- Copy sister Tracker into `pkg/health` with tests.
- Gate inside `LiveLookup` and `Query` so Bouncer’s existing failure-action branches stay the owner of ban/captcha/passthrough.
- Put knobs on reclaim identity (LAPI live identity; AppSec identity). AppSec failure-action enum stays per-router.

**Non-Goals:**
- Changing stream poll `updateMaxFailure` / `StreamHealthy`.
- Captcha-provider health, Redis unreachable, or new failure-action enum values.
- A dedicated health-check goroutine or leaky-bucket limiter.
- Reconstructing client IP (GetRemoteIP remains the owner).

## Decisions

1. **Tumbling window, not leaky bucket.** Ticket named Timeout / Window / Threshold and pointed at the sister Tracker. Alternative: leaky bucket (rate + capacity) — rejected; different knobs, no sister unit, extra complexity for Yaegi.

2. **Gate inside the client, not Bouncer.** `LiveLookup` returns `("", err)` when unhealthy so existing `applyLapiFailureAction` runs. `Query` returns `resultForFailureAction` without `Do`. Alternative: Bouncer checks a new exported `IsUnhealthy` — rejected; the owner of HTTP is the client.

3. **RecordFailure only on backend misbehavior.** LAPI: `queryLiveDecisions` / `crowdsecQuery` errors on the live path, including header-scope queries; not `handleNoStreamCache:banned`; not stream polls (do not hook `crowdsecQuery` globally). AppSec: Do error, 502/503/504, HTTP 500; not unreadable body. Alternative: count every Query error — rejected; unreadable body is the client request.

4. **Timeout 0 or threshold -1 disables skip.** Sister uses threshold < 0. Timeout 0 would trip and immediately recover; treat as never-trip instead so operators have a clear off switch. Window 0 never resets the count (sister).

5. **Defaults 30 / 30 / 5, enabled.** The ticket problem is on by default. Alternative: threshold -1 (opt-in) — rejected; fail-open would still wait 10s per request unless operators discover the knobs.

6. **JSON names without Crowdsec prefix** (`lapiFailureBackoffTimeout`, …). Ticket named them that way. Sibling knobs are `crowdsecLapiFailureAction`. Alternative: `crowdsecLapiFailureBackoffTimeout` — rejected; follow the ticket public surface.

7. **Logs:** Warn on trip, Info on recover, Debug on skipped call. Do not Error every skip.

## Risks / Trade-offs

- [Default enable changes latency profile after 5 timeouts] → README documents defaults and `-1` / `0` opt-out; one blip does not trip.
- [Two routers with different backoff knobs get two HTTP clients to the same host] → same as `HTTPTimeoutSeconds` already on identity.
- [Header-scope live errors increment the Tracker while IP lookup succeeded] → still backend failure; merge result stays today’s swallow.
- [Yaegi copy drift from sister Tracker] → tests pin window/threshold/recover; no extra dependency.

## Migration Plan

Plugin version bump. Operators who want today’s always-call behavior set both thresholds to `-1` (or timeouts to `0`). Rollback: previous tag has no skip. Failure-action YAML is unchanged.

## Open Questions

None. Assumed signals and defaults are on `devstate/explore.md`.
