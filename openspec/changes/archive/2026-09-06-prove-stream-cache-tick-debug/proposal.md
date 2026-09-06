## Why

Upstream v1.6.0-alpha logged `handleStreamCache:updated` at INFO on every stream poll tick and flooded Traefik logs. This fork already emits that line and `handleStreamCache:alreadyUpdated` at DEBUG, but nothing fails if they are promoted back to INFO.

## What Changes

- Add unit tests that capture slog output for both stream-cache tick messages.
- Prove each message is DEBUG (present when the handler is DEBUG, absent at default INFO).
- Fold one requirement onto `core_plugin_lapi_connection`. No product log-level change unless a test cannot be honest without a one-line `Debug` vs `Info` fix.
- **Not BREAKING.**

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_connection`: stream poll ticks MUST log `handleStreamCache:updated` and `handleStreamCache:alreadyUpdated` at DEBUG, not INFO.

## Impact

- `pkg/lapi/client_stream.go` (log call sites under test; no intended behavior change)
- New `pkg/lapi/client_stream_log_test.go`
- Reuses `testStreamLAPI` and cache lease key `"updated"`
