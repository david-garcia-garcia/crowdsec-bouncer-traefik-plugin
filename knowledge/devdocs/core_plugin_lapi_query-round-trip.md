# LAPI query round trip

## Language

**Query round trip**:
One CrowdSec LAPI/CAPI request-response exchange, owned by `sendQuery`: build the request on the stored `transport`, read the status, release the body, and return either the bytes or one error that names its own cause.
_Avoid_: retry loop, recursive `crowdsecQuery`, bodyless replay

## Overview

`crowdsecQuery(url, data)` is the caller-facing entry. `sendQuery(url, data, mayRenewToken)` is the exchange. `mayRenewToken` is the one-shot permission to renew the alone-mode CAPI token: the caller-facing entry passes `true`, the replay and the CAPI login pass `false`. Spec: `core_plugin_lapi_query-round-trip`. The transport it runs on is `core_plugin_lapi_connection.md`.

## How to use

- Call `crowdsecQuery(url, data)` from a LAPI/CAPI caller. Reach for `sendQuery` only where renewal must be forbidden.
- Pass `false` from `getToken`. The login request must never renew, or a persistent `401` recurses without bound.
- Replay the original method and the original body on the alone-mode `401`: `sendQuery(stringURL, data, false)`. Do not replay with a `nil` body — a POST must stay a POST.
- `defer c.drainResponse(res)` immediately after the transport-error check, above every status branch. Drain with `io.Copy(io.Discard, res.Body)`, then `Close`. Closing without draining keeps the connection out of the idle pool.
- Check `isReverseProxyError(res.StatusCode)` below that defer, not beside the transport error. Do not add a `nil` response guard there: the branch is reachable only when `err == nil`.
- Use `%w` only where there is a cause. Name a reverse-proxy status with `statusCode:%d` so `%!w(<nil>)` never reaches an operator.
- Keep `crowdsecQuery:` as the message prefix. It is the operator-facing name of the exchange, not the Go identifier.

## Pattern snippet

```go
res, err := current.httpClient.Do(req)
if err != nil {
	return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
}
defer c.drainResponse(res)
if isReverseProxyError(res.StatusCode) {
	return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s statusCode:%d", stringURL, res.StatusCode)
}
if res.StatusCode == http.StatusUnauthorized && c.crowdsecMode == configuration.AloneMode && mayRenewToken {
	if errToken := c.getToken(); errToken != nil {
		return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
	}
	return c.sendQuery(stringURL, data, false)
}
```

## Key files

- `pkg/lapi/client_http.go`
- `pkg/appsec/query.go`

## Gotchas

- `pkg/appsec` keeps its own `drainResponse` with the same shape (`core_plugin_appsec.md`). Keep the two symmetric; do not hoist one across packages.
- A non-2xx that is not `502/503/504` is drained by the same defer before its status error returns. Draining is not only for the reverse-proxy branch.
- The `401` response is released by the defer, so it is still held while `getToken` and the replay run: up to three sockets during one renewal.
- One replay, ever. `mayRenewToken` is what bounds it — not a counter, not a context.
