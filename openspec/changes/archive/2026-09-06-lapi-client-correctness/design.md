## Context

See proposal.md — Why. After stream-session reclaim (`one-stream-per-lapi-session`), a single `lapi.Client` still spawns concurrent `handleStreamTicker` work from `startTicker`, `Wake`, and `startStream`. Health counters and lease short-circuit are unsynchronized. Live lookup already returns IP LAPI errors to bouncer; scope queries in `mergeLiveScope` log and continue. Explore confirmed defects by code reading; nil-`res` panic was not reproduced (Go `||` short-circuit) but the combined condition is unsafe to maintain.

## Goals / Non-Goals

**Goals:**

- At most one in-flight stream poll body per `lapi.Client` (including initial poll, ticker, and `Wake`).
- Health fields (`isCrowdsecStreamHealthy`, `isCrowdsecStreamStartup`, `updateFailure`) updated only under poll serialization so `streamQuery()` reads are consistent.
- Lease hit on cache key `updated` skips GET only when no poll is in flight; in-flight failure outcome is not masked.
- `crowdsecQuery` never dereferences `res` when `err != nil` or `res == nil`; alone-mode 401 retry replays original method and POST bytes.
- `mergeLiveScope` / `handleNoStreamCache` return error on scope LAPI failure (same semantics as IP unreachable).
- httptest exercises the above via direct helper calls (no ticker timing).

**Non-Goals:**

- Bouncer-side changes beyond surfacing `LiveLookup` error.
- Stream-mode LAPI 401 retry, `getToken` injection, duplicate metrics goroutine at `New`.
- Redis-backed multi-instance lease semantics.
- E2E CrowdSec integration.
- Choosing strongest remediation when both IP and scope return data successfully.

## Decisions

1. **Dedicated stream poll gate** (not `Client.mu`). `Close`/`Sleep`/`Wake` already take `Client.mu`; wrapping the poll body in the same mutex risks deadlock. Use a dedicated mutex or in-flight flag around `handleStreamTicker` / `handleStreamCache` and health mutations. Alternative: channel worker — heavier lifecycle coupling.

2. **Lease short-circuit when poll in flight.** If `updated` lease hits while another poll runs, wait for the in-flight poll or skip GET without resetting failure accounting for the in-flight outcome (explore: do not return unconditional success). Alternative: always skip GET on lease — would still hide in-flight failure today.

3. **`crowdsecQuery` error handling.** Split transport error from status check: if `err != nil || res == nil`, return unreachable before reading status. On alone-mode 401, renew token then recurse with the same URL, method, and body bytes (buffer POST payload before first `Do`). Stream GET 401 stays single-attempt. Alternative: rebuild request from caller each time — callers do not retain body today.

4. **Scope errors propagate.** `mergeLiveScope` returns `(chosen, err)` when any scope `queryLiveDecisions` fails; `handleNoStreamCache` returns `("", err)`. When IP already yields active remediation, bouncer still remediates from `kind` when `err != nil` (existing bouncer behavior). Alternative: fail-open on scope — rejected by requirement.

5. **Tests call poll/lookup directly.** Construct `lapi.Client` with httptest server; invoke `handleStreamTicker`, `handleStreamCache`, or `LiveLookup` synchronously. Cover `updateMaxFailure` 0 vs `-1`, stream JSON apply paths, custom `Transport` returning `(nil, err)`, alone metrics POST + 401, scope 500. Alternative: ticker-based tests — flaky and masked pre-fix races.

## Risks / Trade-offs

- [Scope fail-closed] → Live operators who relied on IP-only pass when scope LAPI fails will now hit `crowdsecLapiFailureAction`. Intended; document in failure-action spec delta.
- [Poll wait on lease] → Slightly longer tick latency when lease hits during in-flight poll. Acceptable vs incorrect health.
- [POST body buffer] → Small memory copy on alone POST paths (metrics, login). Bounded by existing request sizes.
- [Assumed decisions] → Dedicated mutex and scope-always-propagate match explore `assumed` rows; no bouncer change required.

## Migration Plan

Deploy as plugin version bump. No config key changes. Rollback: previous tag restores overlapping polls and scope fail-open. Operators should expect live mode to honor `crowdsecLapiFailureAction` on scope LAPI errors after upgrade.

## Open Questions

None — explore resolved `updateMaxFailure` default (0) and scope propagation policy.
