# Explore
IssueKey: 2026-09-06-upstream-319-stream-cache-log-spam

## Concepts

```
  stream ticker (UpdateIntervalSeconds, default 60s)
            │
            ▼
     handleStreamTicker
            │
            ▼
     handleStreamCache
        │
        ├─ GET cache key "updated" HIT  → log.Debug("handleStreamCache:alreadyUpdated")
        │                                 hydrate Range membership; skip LAPI
        └─ MISS → SET lease, GET /v1/decisions/stream
                  apply New/Deleted → log.Debug("handleStreamCache:updated")

  stream health (INFO, not every poll):
     logInfo(MsgStreamUnhealthy / MsgStreamHealthy) on transition only
```

- Upstream #319: v1.6.0-alpha logged `handleStreamCache:updated` at INFO every poll tick. Closed via PR #324 (revert to DEBUG).
- On this fork `master`, both tick messages already use `c.log.Debug` (`pkg/lapi/client_stream.go:69` and `:129`). Operator-visible stream health uses `logInfo` (`client.go:276-281`).
- Default plugin log level is INFO (`pkg/logger/logger.go` default; `configuration` default `LogINFO`). slog INFO handlers drop Debug (`Enabled` false). Measured: JSON handler at `LevelInfo` omits `handleStreamCache:updated`; same handler at `LevelDebug` includes it; INFO still emits `crowdsec stream became healthy`.
- Existing `TestHandleStreamCacheLeaseHitHydrates` calls `handleStreamCache` on a lease hit but uses `logger.New("ERROR", "")` and does not assert log level. `TestClient_LifecycleLogs` captures INFO lifecycle lines, not cache ticks.
- Usage packet `knowledge/devdocs/core_plugin_middleware.md` already states: lifecycle INFO is `started|sleeping|waking|closed`; stream health is `unhealthy|healthy` (not every poll). That is enough to call the subsystem. No Language gap. Research indexes (`ext_crowdsec`, `ext_traefik`) are not needed: this is our slog level, not a CrowdSec/Traefik API fact.
- Identity is not reconstructed on this path. No reclaim / `sync.Once` change.

## Decisions

- **Product code:** none unless a test cannot be honest without a one-line `Debug` vs `Info` fix (current tree already uses Debug).
- **Test technique:** slog JSON-handler capture on a `bytes.Buffer`, same pattern as `pkg/lapi/session_test.go` `TestClient_LifecycleLogs`. Not static inspection of `log.Debug` call sites (that would not fail if someone switched those strings to `Info`). Do not copy `pkg/reclaim` `recHandler` into lapi; buffer + JSON is the in-package owner.
- **Coverage:** both messages. Lease-hit (`alreadyUpdated`) via cache key `"updated"` like `TestHandleStreamCacheLeaseHitHydrates`. Lease-miss (`updated`) via `testStreamLAPI` + a Client that can `crowdsecQuery` (reuse session-test mock LAPI; `OpenStream` with `StreamStartupBlock` or a Client with HTTP fields). Two assertions per path: (1) `LevelInfo` handler MUST NOT contain the tick message (operator spam proof); (2) `LevelDebug` handler MUST contain it at debug (the line still exists).
- **File:** new `pkg/lapi/client_stream_log_test.go`. Do not pile this onto `client_range_test.go` (that file owns Range hydrate).
- **Spec:** fold a stream-tick log-level requirement onto `core_plugin_lapi_connection` (FindSpecHost at propose). Not a new leaf: one invariant of the existing stream ticker, not a new capability.
- **Devdocs:** no explore write. Middleware gotcha already separates poll ticks from health INFO. Implement/devdocsimpact may add the two DEBUG message names if the apply wants them on that packet.

## Open questions

- Q: slog record capture vs static inspection of `log.Debug` call sites?
  Decision: assumed — slog JSON buffer capture (INFO absent + DEBUG present) for both tick messages.
  By: explore

- Q: Is a lease-miss (full LAPI fetch) test needed in addition to lease-hit?
  Decision: assumed — yes; both strings were the upstream spam surface; cover `updated` and `alreadyUpdated`.
  By: explore

- Q: Spec host for the log-level invariant?
  Decision: resolved — fold onto `core_plugin_lapi_connection` (FindSpecHost: fold, high; candidates: core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim, core_cache_client_isolated-store).
  By: propose
