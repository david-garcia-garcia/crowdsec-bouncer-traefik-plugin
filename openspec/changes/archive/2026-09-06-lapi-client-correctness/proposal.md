## Why

`pkg/lapi` on `master` allows overlapping stream polls that race health state and can hide in-flight failures behind lease short-circuits; `crowdsecQuery` is fragile on transport errors and drops alone-mode POST bodies on 401 retry; live header-scope LAPI errors fail open so `crowdsecLapiFailureAction` never runs. These are production enforcement gaps on shared LAPI paths.

## What Changes

- Serialize stream polling per `lapi.Client` so health fields and stream GETs cannot overlap; lease short-circuit must not treat success while another poll is failing.
- Harden `crowdsecQuery` against nil response on transport error; return unreachable without panic.
- Preserve HTTP method and replay POST body on alone-mode 401 token renewal retry.
- Propagate header-scope LAPI errors from live lookup so bouncer can apply `crowdsecLapiFailureAction` (no bouncer code change).
- Add httptest coverage: stream health threshold/recovery, stream JSON apply (IP/header/range/delete), nil-response transport, alone 401 POST retry, live scope error path.

No **BREAKING** public JSON config keys. Stream-mode LAPI 401 retry stays out of scope (not retried today).

## Capabilities

### New Capabilities

- `core_plugin_lapi_stream-poll`: At-most-one in-flight stream poll per client; synchronized health fields; lease behavior when a poll is already running.
- `core_plugin_lapi_http-query`: Safe LAPI HTTP helper on transport failure; alone-mode 401 retry preserves method and POST body.

### Modified Capabilities

- `core_plugin_lapi_failure-action`: Live header-scope LAPI query failures SHALL surface like IP unreachable errors so `crowdsecLapiFailureAction` applies.

## Impact

- `pkg/lapi/client.go`, `client_stream.go`, `client_http.go`, `client_live.go`, `client_decisions.go` (stream poll gate, health sync, HTTP helper, scope error propagation).
- `pkg/lapi/client_metrics.go` (benefits from POST body replay on alone 401).
- `pkg/lapi/*_test.go` (new httptest cases; direct calls to poll/lookup helpers, no ticker timing).
- Specs: `core_plugin_lapi_stream-poll`, `core_plugin_lapi_http-query` (new); `core_plugin_lapi_failure-action` (modified).
- Out of scope: bouncer `applyLapiFailureAction` wiring, stream-mode 401 retry, Redis multi-instance lease, E2E CrowdSec.
