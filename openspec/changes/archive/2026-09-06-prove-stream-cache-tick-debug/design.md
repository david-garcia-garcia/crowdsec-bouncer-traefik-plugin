## Context

See proposal.md — Why. `handleStreamCache` already calls `c.log.Debug` on both tick paths. Default `pkg/logger` level is INFO, which drops Debug. Existing `TestHandleStreamCacheLeaseHitHydrates` exercises the lease-hit path at ERROR and does not assert level. `TestClient_LifecycleLogs` captures INFO lifecycle lines with a JSON buffer.

## Goals / Non-Goals

**Goals:**
- Tests that fail if either tick message is promoted to INFO.
- Cover lease-miss (`updated`) and lease-hit (`alreadyUpdated`).

**Non-Goals:**
- Changing product log calls unless a test cannot be honest without a one-line `Debug` vs `Info` fix.
- Asserting stream-health INFO lines.
- Static inspection of source call sites.

## Decisions

- **Capture:** `slog.NewJSONHandler` on a `bytes.Buffer`, same pattern as `TestClient_LifecycleLogs`. Alternative considered: copy `pkg/reclaim` `recHandler` — rejected; lapi already owns JSON-buffer capture.
- **Two levels per path:** INFO handler MUST NOT contain the tick message; DEBUG handler MUST contain it. Alternative: DEBUG-only presence — rejected; that would still pass if the line were Info (Info is also enabled at Debug).
- **Lease miss:** reuse `testStreamLAPI` and a Client that can `crowdsecQuery` (`OpenStream` with `StreamStartupBlock` or HTTP-wired Client). Do not start a 60s wait.
- **File:** `pkg/lapi/client_stream_log_test.go`. Alternative: extend `client_range_test.go` — rejected; that file owns Range hydrate.

## Risks / Trade-offs

- [OpenStream starts a ticker] → use `StreamStartupBlock` for the first poll, then call `handleStreamCache` again for lease hit; Close the client in cleanup.
- [JSON `level` field type] → assert message substring; slog default JSON uses `"level":"DEBUG"` / `"INFO"` with this repo's ReplaceAttr only on `logger.New`. Tests that build `slog.NewJSONHandler` directly get slog's default `DEBUG`/`INFO` strings.

## Migration Plan

None — tests only.

## Open Questions

None.
