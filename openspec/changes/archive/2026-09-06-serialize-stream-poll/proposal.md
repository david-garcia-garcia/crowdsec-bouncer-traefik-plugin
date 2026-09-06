## Why

On `master`, one `lapi.Client` can run overlapping `handleStreamTicker` goroutines (`go work()` per tick plus `Wake()`). A cache lease hit returns success while another poll is still in flight, so failure counters reset and CrowdSec’s stream cursor can be raced. Upstream #377 saw `GET /v1/decisions/stream` go silent for ~20 minutes while metrics still posted; newly banned IPs did not reach the Traefik cache.

## What Changes

- At most one in-flight `handleStreamCache` per `lapi.Client`. Extra ticker/`Wake` work TryLock-skips; a skip is not a successful poll.
- `crowdsecQuery` is bounded by `HTTPTimeoutSeconds` via a request context deadline (in addition to `http.Client.Timeout`).
- Tests: overlapping Wake/ticker yield one in-flight stream GET; in-process skip does not clear `updateFailure`; timeout bounds `crowdsecQuery`.

No **BREAKING** public JSON config keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: one in-flight `handleStreamCache` per Client; skip-if-busy is not success; ticker work stays async so a hung poll cannot freeze the ticker.
- `core_plugin_lapi_connection`: `crowdsecQuery` applies `HTTPTimeoutSeconds` as a request deadline and does not read a nil response on transport error.

## Impact

- `pkg/lapi/client.go`, `client_stream.go`, `client_http.go`
- Unit tests in `pkg/lapi`
- Usage gotcha on `knowledge/devdocs/core_plugin_middleware.md` after apply
