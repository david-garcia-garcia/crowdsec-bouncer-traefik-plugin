# Devdocs impact
change: lapi-client-correctness

## Units
- LAPI Client — subsystem — `pkg/lapi.Client` / `core_plugin_middleware.md`
- LAPI stream poll — subsystem — `pkg/lapi/client_stream.go` / `core_plugin_lapi_stream-poll`
- LAPI HTTP query — pattern — `pkg/lapi/client_http.go` (`crowdsecQuery`) / `core_plugin_lapi_http-query`
- Live LAPI failure-action — behavior — `pkg/lapi/client_live.go` / `core_plugin_lapi_failure-action`

## Findings
- [x] missing-packet  LAPI stream poll — no packet; middleware gotchas mention stream health transitions only, not `streamPollMu`, lease clear on GET failure, or `updateMaxFailure` threshold
- [x] missing-packet  LAPI HTTP query — no packet for shared `crowdsecQuery` helper (transport guard, alone-mode 401 POST replay)
- [x] stale-usage  Plugin middleware New — How-to says live LAPI errors use `crowdsecLapiFailureAction` but omits header-scope query failures (now propagated from `LiveLookup`)
