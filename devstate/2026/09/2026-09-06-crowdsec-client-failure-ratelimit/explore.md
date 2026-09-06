# Explore
IssueKey: 2026-09-06-crowdsec-client-failure-ratelimit

## Concepts

```
  request (live/none)                         request (any mode, AppSec on)
        │                                              │
        ▼                                              ▼
  cache hit? ──yes──▶ remediate / pass                 │
        │ no                                           │
        ▼                                              ▼
  LAPI Tracker.IsUnhealthy?                    AppSec Tracker.IsUnhealthy?
        │ yes → skip HTTP, apply               yes → skip HTTP, apply
        │       crowdsecLapiFailureAction             crowdsecAppsecFailureAction
        ▼ no                                           ▼ no
  LiveLookup / queryLiveDecisions              appsec.Query Do()
        │ fail → RecordFailure                         │ fail (unreachable/500) → RecordFailure
        │ success → existing cache/remediate           │ success → existing envelope
        ▼
  after N fails in window → backoff Timeout
  after Timeout → auto-recover; next request is the probe
```

**Tracker** (copy of sister `traefik-modsecurity` `pkg/health.Tracker`): tumbling-window failure count, trip to unhealthy at threshold, timed auto-recover. Not a leaky bucket. Not `UpdateMaxFailure` / `StreamHealthy`.

**Failure action** (already shipped): what to do *instead of a usable verdict* (`passthrough` / `ban` / `captcha`). Unchanged. Backoff only decides *whether to wait on HTTP* before that action.

**Owner**: one Tracker on the reclaimed `lapi.Client` (live/none request path) and one on the reclaimed `appsec.Client`. Not on Bouncer. Not a package global. Constructor `ctx` remains the reclaim holder (`std_go_reclaim`).

## Decisions

### Algorithm: tumbling window, not leaky bucket

Ticket named Timeout / BucketWindow / BucketThreshold and pointed at [traefik-modsecurity `pkg/health`](https://github.com/david-garcia-garcia/traefik-modsecurity/tree/main/pkg/health). Leaky-bucket was optional.

Copy that Tracker into this module as `pkg/health` (Yaegi cannot depend on another Traefik plugin). Same three knobs. No ticker goroutine. `failureThreshold < 0` never trips. `failureWindow == 0` never resets the counter. Auto-recover when `now > shutdownUntil`; next outbound call is the implicit probe. Success does not decrement (sister behavior).

Leaky-bucket would need different knobs (rate + capacity) and is not the sister unit. Rejected.

### Where the gate lives

Inside the owner that talks to the backend, so Bouncer’s existing failure-action branches keep working:

- `lapi.Client.LiveLookup`: if unhealthy, return `("", errBackoff)` without HTTP. Bouncer already calls `applyLapiFailureAction` when `err != nil` and the value is not an active remediation.
- `lapi.queryLiveDecisions` / `crowdsecQuery` errors on the live path: `RecordFailure`. Do **not** record `handleNoStreamCache:banned` (that is a decision). Do **not** record stream/alone poll failures (`UpdateMaxFailure` stays the stream counter).
- `appsec.Client.Query`: if unhealthy, return `resultForFailureAction` without `Do`. Record on transport / 502/503/504 / HTTP 500 only. Do **not** record unreadable-body (client request, not listener health) or structured AppSec envelopes.

Header-scope live queries (`mergeLiveScope`) go through `queryLiveDecisions`; their errors count. Today those errors are swallowed for the merge result; they still increment the tracker.

### Stream / alone / appsec modes

- Stream/alone request path never calls `LiveLookup`. LAPI Tracker is unused there. `StreamHealthy` + `updateMaxFailure` stay as today.
- AppSec still runs on the pass path in every mode (including stream). AppSec Tracker applies whenever `crowdsecAppsecEnabled`.
- `crowdsecMode: appsec`: no LAPI client; AppSec Tracker only.
- `none`: every request hits LiveLookup; LAPI Tracker is the main win.

### Reclaim identity

LAPI live/none identity already includes `HTTPTimeoutSeconds` and `LapiFailureAction`. Add the three LAPI backoff knobs there so two routers cannot share one `lapi.Client` with disagreeing trip settings.

AppSec identity already includes `HTTPTimeoutSeconds`. Add the three AppSec backoff knobs there. `crowdsecAppsecFailureAction` stays per-router on Bouncer (existing spec). Health of the listener is shared; fallback enum can still differ per route.

Stream session key stays URL+key (no LAPI backoff fields). Stream poller does not use this Tracker.

### Defaults and opt-out

Enable by default so fail-open is actually fast under outage (the ticket problem). Opt-out: threshold `-1` (sister) **or** timeout `0` (never skip).

| Knob | Default | Notes |
|------|---------|--------|
| `lapiFailureBackoffTimeout` / `appsecFailureBackoffTimeout` | `30` seconds | Unhealthy duration. `0` disables skip. |
| `lapiFailureBackoffBucketWindow` / `appsecFailureBackoffBucketWindow` | `30` seconds | Tumbling window. `0` = counter never resets. |
| `lapiFailureBackoffBucketThreshold` / `appsecFailureBackoffBucketThreshold` | `5` | Failures in the window to trip. `-1` never trips. Must be `>= -1`. |

Five timeouts in 30s then 30s skip: one blip does not trip; a down or hung LAPI/AppSec does, after ~5×`HTTPTimeoutSeconds` worst case, then skips.

### Logs

Warn when a tracker trips; Info when backoff expires (sister). Debug on skipped calls. Do not Error every skipped request.

### Docs / tests

Public README next to `HTTPTimeoutSeconds` / failure-action knobs. Unit tests for `pkg/health` (port sister cases: window reset, threshold, opt-out, auto-recover, concurrent IsUnhealthy). Client tests: skip HTTP while unhealthy; RecordFailure on live query error / AppSec unreachable; unreadable body does not trip AppSec; banned live decision does not trip LAPI.

## Open questions

- Q: Tumbling window or leaky bucket?
  Decision: resolved — tumbling-window `pkg/health.Tracker` copied from traefik-modsecurity; keep ticket knob names.
  By: explore

- Q: Exact failure signals that increment the bucket?
  Decision: assumed — LAPI live: `queryLiveDecisions` / `crowdsecQuery` errors and live JSON/duration parse errors, including header-scope queries; not `handleNoStreamCache:banned`; not stream polls. AppSec: `Do` error, 502/503/504, HTTP 500; not unreadable body, not structured envelopes.
  By: explore

- Q: One tracker per reclaimed client or per middleware?
  Decision: resolved — one Tracker on `lapi.Client` and one on `appsec.Client`. Bouncer does not own health. Knobs on reclaim identity (except AppSec failure-action enum, which stays per-router).
  By: explore

- Q: Default knob values and opt-out?
  Decision: assumed — timeout 30s, window 30s, threshold 5; disable with threshold `-1` or timeout `0`. Window `0` never resets the counter (sister).
  By: explore

- Q: Backoff expiry alone, or require a successful probe?
  Decision: resolved — sister auto-recover on timeout; next request is the implicit probe. No dedicated health-check goroutine.
  By: explore

- Q: Interaction with `StreamHealthy` / `updateMaxFailure`?
  Decision: resolved — leave stream poll semantics unchanged. LAPI Tracker is live/none request path only. AppSec Tracker still applies on stream pass path.
  By: explore

- Q: Who already owns client identity (IP / trust hop) for this change?
  Decision: resolved — no identity reconstruction. `GetRemoteIP` / `clientRequest` stay the owner; Tracker does not see the client address.
  By: explore
