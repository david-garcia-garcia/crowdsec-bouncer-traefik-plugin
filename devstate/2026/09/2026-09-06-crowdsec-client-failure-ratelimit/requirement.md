# Requirement
IssueKey: 2026-09-06-crowdsec-client-failure-ratelimit

## Problem

AppSec, live, and none modes call CrowdSec LAPI or AppSec on every request. When those backends are down or slow, each request still waits for `HTTPTimeoutSeconds` before the existing failure-action path runs (passthrough, ban, or captcha). Under outage or overload that adds latency on the critical path even when operators chose fail-open.

Stream/alone modes poll LAPI on a ticker and flip `StreamHealthy` after `updateMaxFailure`, but live/none still hit LAPI per miss and AppSec still runs on every pass path with no skip-after-repeated-failures behavior.

## Current (code)

- `pkg/bouncer/bouncer.go` — live/none call `lapiClient.LiveLookup` per request (`ServeHTTP` ~212–228); on error applies `applyLapiFailureAction` using `CrowdsecLapiFailureAction` (`applyLapiFailureAction` ~232–241). AppSec runs in `handleNextServeHTTP` → `applyAppsecServeHTTP` (~304–341) with no pre-call health gate.
- `pkg/lapi/client_live.go` — `LiveLookup` → `queryLiveDecisions` → `crowdsecQuery`; transport/HTTP errors return to bouncer with no backoff state (`queryLiveDecisions` in `pkg/lapi/client_decisions.go` ~77–87).
- `pkg/appsec/query.go` — `Query` always `httpClient.Do`; unreachable/500 map to `FailureAction` via `resultForFailureAction` (~98–107); no skip when backend recently failed repeatedly.
- `pkg/lapi/client_stream.go` — background stream poll tracks `isCrowdsecStreamHealthy` via `updateMaxFailure` (~48–63); separate from per-request live/AppSec paths.
- `pkg/configuration/configuration.go` — `CrowdsecLapiFailureAction`, `CrowdsecAppsecFailureAction`, `UpdateMaxFailure`, `HTTPTimeoutSeconds` exist; no `*FailureBackoff*` knobs (`Config` ~71–92).
- `not found` — any request-path failure backoff / rate-limit tracker for LAPI or AppSec in this repo.

Reference (third party): `github.com/david-garcia-garcia/traefik-modsecurity@645f4a25` `pkg/health/Tracker` — tumbling-window failure count, trip to unhealthy, timed auto-recover; `serve.go` skips sidecar HTTP while unhealthy (`knowledge/research/ext_traefik-modsecurity_health_tracker/notes.md`).

## Desired

When LAPI (live/none request path) or AppSec misbehaves (timeouts, transport errors, and the failure cases already counted today), count failures in a configurable window; after a configurable threshold, enter a backoff period and **skip** further outbound calls for that backend until backoff expires or a probe succeeds.

During backoff, apply the existing failure-action semantics (passthrough / ban / captcha) without waiting for HTTP timeout on each request. Restore normal calls when the backend is healthy again.

Expose separate knobs for LAPI and AppSec (names may follow the chosen limiter; ticket proposes `lapiFailureBackoffTimeout`, `lapiFailureBackoffBucketWindow`, `lapiFailureBackoffBucketThreshold`, and AppSec equivalents). Leaky-bucket is acceptable if well tested; adjust knob names to match.

## Affected

- `pkg/configuration/` — new config fields, defaults, validation
- `pkg/lapi/` — live/none query path; possibly shared tracker on reclaimed `Client`
- `pkg/appsec/` — `Query` path and reclaimed `Client`
- `pkg/bouncer/bouncer.go` — gate before `LiveLookup` and AppSec call
- `plugin.go` — wire trackers on reclaimed clients if needed
- Tests for tracker + integration with failure actions
- README / operator docs for new knobs

## Out of scope

- Changing stream/alone background poll semantics beyond any shared tracker wiring (`updateMaxFailure` / `StreamHealthy` behavior as-is unless ticket explicitly ties them in explore).
- Replacing `CrowdsecLapiFailureAction` / `CrowdsecAppsecFailureAction` enum values.
- Captcha provider health backoff.
- Redis cache unreachable behavior.
- Official CrowdSec spec changes.

## Unknowns

- Exact failure signals that increment the bucket (live LAPI: all `crowdsecQuery` errors vs only transport/5xx; AppSec: align with existing unreachable vs 500 split or unify).
- Whether live/none and AppSec share one tracker per reclaimed client or per middleware.
- Default knob values and opt-out (threshold `-1` like reference tracker?).
- Whether backoff expiry alone restores service or requires a successful probe request.
- Stream mode: ticket text emphasizes request-path modes; interaction with existing `StreamHealthy` needs explore.

## Tensions

- Ticket names tumbling-window knobs; allows leaky-bucket if tests are strong — explore must pick one and rename knobs.
- Reference uses tumbling window; dev.to article covers token/leaky bucket — not a CrowdSec official pattern.
- Existing `CrowdsecLapiFailureAction` defaults and stream `updateMaxFailure` already handle “what to do on failure”; this change adds “stop calling for a while” — both must compose without double-ban or silent pass inconsistencies.
