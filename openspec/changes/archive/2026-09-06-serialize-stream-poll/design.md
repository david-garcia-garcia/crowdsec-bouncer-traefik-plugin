## Context

See proposal.md — Why. `startTicker` already uses `go work()` so the ticker loop does not wait. `Wake` also starts `go handleStreamTicker()`. `handleStreamCache` SETs lease key `updated` then calls LAPI; a second goroutine can GET the lease and return nil, which `handleStreamTicker` treats as success. Metrics already serializes POSTs with `reportMu`. Native Go `http.Client.Timeout` already bounds `crowdsecQuery`; a request context deadline is defense in depth. Reclaim Sleep/Wake and one ticker per session stay as they are.

## Goals / Non-Goals

**Goals:**
- At most one in-flight stream GET per Client.
- In-process skip is not success.
- Ticker loop never waits on LAPI.
- `crowdsecQuery` always bounded by `HTTPTimeoutSeconds`.

**Non-Goals:**
- Redis SET NX / multi-instance lease races.
- Changing metrics ticker behavior.
- Reclaim Open/Sleep/Wake wiring or a second poller per session.
- Encoding a 20-minute constant. Yaegi-specific timer workarounds.

## Decisions

1. **TryLock skip, not mutex-wait.** `streamPollMu.TryLock` at the start of `handleStreamTicker`. Failed lock returns without touching `updateFailure` / `isCrowdsecStreamHealthy`. Alternative: `Lock()` wait — queues `go work()` goroutines behind a hung poll.

2. **Keep `go work()` on `startTicker`.** The reporter’s freeze is a ticker that waited on work. Alternative: sync work — metrics would still run (separate ticker) but stream ticks would stop until the GET finished.

3. **Request context deadline on `crowdsecQuery`.** `context.WithTimeout` from `HTTPTimeoutSeconds` on `http.NewRequest`. Guard `res == nil` before status checks. Alternative: rely only on `Client.Timeout` — already works in native Go; context covers Do paths and tests.

4. **Lease hit after owning the slot stays success.** TryLock first; then existing `updated` GET. Redis sibling skip still healthy. Alternative: treat every lease hit as skip-not-success — would mark unhealthy when another instance is polling on schedule.

## Risks / Trade-offs

- [Skip drops a tick during a long poll] → next tick after unlock polls; timeout bounds the wait. Better than overlapping GETs on one CrowdSec cursor.
- [Yaegi ignores timers] → still serialize polls; cannot prove 20-minute TCP stalls in unit tests. Log the timeout error when it does fire.
- [Two first-miss GETs before SET] → TryLock removes that in-process race. Cross-process remains out of scope.

## Migration Plan

Plugin version bump. No config key change. Rollback: previous tag restores overlapping polls.
