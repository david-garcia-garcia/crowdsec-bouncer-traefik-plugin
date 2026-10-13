## Context

See proposal.md — Why. Dest `master` already floors lease duration in `pkg/lapi/client_stream.go` (`leaseDuration := c.updateInterval - 1; if leaseDuration < 1 { leaseDuration = 1 }`). `TestHandleStreamCacheLeaseHitHydrates` pre-seeds `updated` with TTL 60. In-memory `golang-ttl-map` `Set` is a no-op at TTL 0.

FindSpecHost: new `core_plugin_lapi_stream-lease`. Confidence high. Candidates: `core_plugin_lapi_connection` (package layout, not lease TTL), `core_plugin_lapi_failure-action`, `core_plugin_middleware_instance-reclaim` (one ticker per session, not lease duration), `core_cache_client_isolated-store` (prefix isolation, not this key's TTL).

## Goals / Non-Goals

**Goals:**
- A miss-path test at `updateInterval == 1` that fails if the lease is not stored.
- Spec leaf for that floor.

**Non-Goals:**
- Changing production `client_stream.go` unless the test cannot be honest without a one-line fix.
- Redis backend or `SET EX 0` caller errors.
- Sleeping to prove 1s expiry.

## Decisions

1. **In-memory cache only.** TTL 0 is a no-op in `golang-ttl-map`; that is enough to catch a regression to `updateInterval - 1` with no floor. Redis EX 0 is a separate surfacing note (requirement out of scope).
2. **New `pkg/lapi/client_stream_test.go`.** Same package as `handleStreamCache`. Reuse `testStreamLAPI` and `newTestRangeClient`. Do not extend the Range hydrate lease-hit test.
3. **Assert store + skip, not expiry.** After first miss: `Get("updated")` succeeds and `streamFetches` is 1. Second `handleStreamCache`: `streamFetches` stays 1 (or mock LAPI hits stay 1).
4. **New spec leaf.** Connection spec is file ownership. Lease TTL is a distinct LAPI stream guard.

## Risks / Trade-offs

- [Test needs HTTP fields on a hand-built Client] → Set scheme, host, path, stream route, and `httpClient` from `testStreamLAPI`; same package already does this in `session_test.go`.
- [Lease is SET before LAPI returns] → First call still counts as one fetch even if parse fails; the test uses empty `new`/`deleted` JSON so the miss path completes.

## Migration Plan

No operator config change. Rollback is revert.
