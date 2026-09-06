# LAPI HTTP query

## Overview

`crowdsecQuery` is the shared LAPI/CAPI round-trip for stream GET, live GET, metrics POST, and alone-mode login. Non-empty `data` selects POST with a copied body buffer. Transport failures and nil responses return unreachable without reading status. Alone-mode HTTP 401 renews the token and retries once with the same method and body bytes.

## How to use

- Route all LAPI/CAPI HTTP through `crowdsecQuery` or `crowdsecQueryWithMethod`; do not duplicate auth or retry logic.
- Check `err != nil || res == nil` before reading `res.StatusCode` or the body.
- Treat reverse-proxy 502/503/504 as unreachable (same as transport error).
- Alone mode only: on 401, call `getToken()` then `crowdsecQueryWithMethod` with the original method and `postBody` slice. Do not recurse with `nil` data (that downgrades POST to GET).
- Stream and live GET paths outside alone mode: 401 is a single-attempt failure; do not apply token renewal retry.

## Pattern snippet

```go
body, err := client.crowdsecQuery(metricsURL, payload) // POST when len(payload) > 0
if err != nil {
	// unreachable — live lookup error or stream poll failure
}
```

## Key files

- `pkg/lapi/client_http.go`
- `pkg/lapi/client_metrics.go` (metrics POST)
- `pkg/lapi/client_stream.go` (stream GET)
- `pkg/lapi/client_decisions.go` (live GET)

## Gotchas

- Copy POST bytes before the first `Do`; the retry must replay the same payload (metrics POST after token expiry).
- `getToken` itself uses `crowdsecQuery` with a POST login body; alone-mode 401 on login follows the same retry path.
- Expected success is any 2xx status; metrics POST success from LAPI is typically 201.
