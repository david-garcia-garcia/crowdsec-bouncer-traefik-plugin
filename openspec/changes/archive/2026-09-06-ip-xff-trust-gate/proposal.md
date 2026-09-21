## Why

`GetRemoteIP` walks forwarded headers without verifying `req.RemoteAddr` is a trusted proxy. A direct client can forge `X-Forwarded-For` and be identified as another IP for ban, captcha, and cache decisions. With the default empty trusted-hop pool, any header value wins over the socket peer.

## What Changes

- `GetRemoteIP` gates the forwarded-header walk: only when the host from `req.RemoteAddr` is in the trusted-hop pool (`ForwardedHeadersTrustedIPs` via `PoolStrategy.Checker`).
- Empty trusted-hop pool ignores forwarded headers entirely; client address comes from `RemoteAddr` only.
- Unparseable-hop fail-closed behavior unchanged; add unit tests for spoofing, empty pool, malformed hops, and port-suffixed hops.
- **Not BREAKING.** No new public config keys. Operators who already list trusted proxies in `forwardedHeadersTrustedIps` gain correct behavior; direct clients can no longer spoof.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: GetRemoteIP SHALL require trusted `RemoteAddr` before honoring forwarded headers; empty pool SHALL ignore headers.

## Impact

- `pkg/ip/checker.go` (`GetRemoteIP`)
- `pkg/ip/checker_test.go` (new and updated cases)
- `knowledge/devdocs/core_plugin_ip.md` (GetRemoteIP gate wording)
