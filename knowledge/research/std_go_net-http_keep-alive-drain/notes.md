# HTTP keep-alive response drain

When Go `net/http.Client.Do` can reuse a persistent TCP connection.

Fetched: 2026-09-17. Pin: Go 1.25.6.

## Read to EOF and Close

`Client.Do` documents: if the returned error is nil, `Response.Body` is non-nil and the caller must close it. If the Body is not **both read to EOF and closed**, the Client’s RoundTripper (typically `Transport`) may not reuse a persistent TCP connection for a later keep-alive request. ([Client.Do](https://pkg.go.dev/net/http#Client.Do), extract `.sources/client-do.md`)

On error, any Response can be ignored. A non-nil Response with a non-nil error only occurs when `CheckRedirect` fails, and that Body is already closed.

## What this means for an early return after a 5xx

A 502/503/504 is not a `Do` error (`Do` only fails on policy or transport). The Response is live. Returning without draining and closing the Body leaves that connection out of the idle pool — exactly while the peer is unhealthy and keep-alive reuse would matter most.

Transport errors (`err != nil`, typically `res == nil`) have no body to drain.

## Sources

- Official: [net/http.Client.Do](https://pkg.go.dev/net/http#Client.Do)
- Extracts: `.sources/`
