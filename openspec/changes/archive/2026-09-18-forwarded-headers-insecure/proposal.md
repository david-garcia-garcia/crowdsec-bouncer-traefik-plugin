## Why

`ForwardedHeadersTrustedIPs` both gates the socket peer and skips hops inside the header. A catch-all such as `0.0.0.0/0` plus `::/0` passes the peer check, then treats the header value as a trusted hop, so `GetRemoteIP` falls back to `RemoteAddr` with no log. Operators behind a CDN that already trust Traefik's entrypoint `forwardedHeaders` have no way to say "use the header Traefik sanitized".

## What Changes

- Add `forwardedHeadersInsecure` (default false) on `Config`.
- Flag off keeps today's peer gate and hop walk, including the silent catch-all.
- Flag on: `GetRemoteIP` still requires `RemoteAddr` host:port, then reads the whole trimmed header with no hop walk and no checker.
- When the flag is on and `ForwardedHeadersCustomName` is still `X-Forwarded-For`, `bouncer.New` uses `X-Real-Ip` and logs that name once at Info.
- **Not BREAKING.** Default false preserves current outcomes.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: GetRemoteIP peer gate is the default path; `ForwardedHeadersInsecure` is a separate requirement that reads the header as a single client address.

## Impact

- `pkg/configuration/configuration.go`
- `pkg/ip/checker.go` (`GetRemoteIP` signature)
- `pkg/bouncer/bouncer.go` (effective header + call site)
- `pkg/ip/zzz_checker_test.go`, `pkg/configuration/zzz_configuration_test.go`, `pkg/bouncer/zzz_bouncer_test.go`
- `knowledge/devdocs/core_plugin_ip.md`
- `README.md` forwarded-headers option entries
