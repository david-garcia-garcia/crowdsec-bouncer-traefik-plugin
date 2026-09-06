## Why

The AppSec `Query` forward path leaks HTTP connections on 502/503/504, sends stale body metadata to the listener, always bans on response read failures, and silently drops POST bodies when `crowdsecAppsecBodyLimit` is `0`.

## What Changes

- Drain AppSec response bodies on every non-nil response before failure-action return.
- Filter hop-by-hop and body-size headers when copying client headers; set `Content-Length` from bytes actually forwarded.
- Apply `crowdsecAppsecFailureAction` to response body read/transport errors.
- Treat `crowdsecAppsecBodyLimit: 0` as unlimited body forward (explicit contract; no silent GET downgrade).
- Add unit tests for all four paths.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `core_plugin_appsec_client`: forward-path drain, header rebuild, body-limit-zero semantics.
- `core_plugin_appsec_failure-action`: response read errors use failure action.

## Impact

- `pkg/appsec/query.go`, `query_test.go`, `failure_action_test.go`
- `pkg/appsec/test_client.go` (test helper for body limit)
