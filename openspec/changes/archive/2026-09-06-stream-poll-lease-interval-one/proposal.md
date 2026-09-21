## Why

On `master`, `handleStreamCache` already floors the stream poll lease TTL at 1 second so `updateIntervalSeconds: 1` stores cache key `updated`. Upstream #370 used `updateInterval - 1` (TTL 0), which neither the in-memory map nor Redis stores. No test on `master` proves the floor, so a regression would silently restore N-polls-per-tick.

## What Changes

- Add a unit test that, with `updateInterval` 1, a stream cache miss stores `updated` and a second call skips LAPI.
- Add spec `core_plugin_lapi_stream-lease` for that lease duration floor.
- Do not change production `pkg/lapi/client_stream.go` unless a test cannot be honest without a one-line fix.
- Do not add Redis `SET EX 0` tests or TTL-expiry sleeps.

## Capabilities

### New Capabilities

- `core_plugin_lapi_stream-lease`: stream poll lease key `updated` is stored with TTL at least 1 second, including when `updateIntervalSeconds` is 1, so a later `handleStreamCache` in the same interval skips LAPI.

### Modified Capabilities

None.

## Impact

- `pkg/lapi/client_stream_test.go` (new)
- `openspec/specs/core_plugin_lapi_stream-lease/spec.md` (archive sync)
- Plugin public config unchanged. Not **BREAKING**.
