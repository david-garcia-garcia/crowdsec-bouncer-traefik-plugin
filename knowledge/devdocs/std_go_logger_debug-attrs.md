# Request-path Trace attributes

## Language

**Request-path Trace**:
A Trace call on the request hot path (`ServeHTTP` allow/hit, captcha Check/Validate) that must not format a string unless the logger's level includes Trace.
_Avoid_: Sprintf-then-Trace, concatenating the message before `Trace`, logging per-request breadcrumbs at Debug, logging failures at Trace

**Remediating TRACE**:
A request-path Trace after a store-hit or LiveLookup remediation. Stem is `ServeHTTP` (store hit) or `ServeHTTP:LiveLookup` (live/none miss). Fields are `ip`, the kind letter (`remediation` or `isBanned`), and present header-mapped values as slog group `scopes`.
_Avoid_: cache, cache=hit, a winning-scope field, a Range CIDR, re-reading headers, requiring `scopes` on the allow/trust breadcrumb

**scopes group**:
A slog group on remediating TRACE whose keys are present `RequestScopeValues` CrowdSec scope names and whose values are those header values.
_Avoid_: an empty group, flattening as `scope.Country`, inventing keys for missing headers

## Overview

`slog.Logger` has no Trace method. Use `logger.Trace` (`slog.Level(-8)`). Call-site arguments are still evaluated before `Enabled`, so pass a message stem and the fields as slog attributes instead of `fmt.Sprintf`. Remediating TRACE reuses `req.remoteIP` and the `RequestScopeValues` map already in hand; omit group `scopes` when that map is empty. DEBUG still covers construct-time, stream-tick, and request-path failure lines.

## How to use

- Call `logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)` for the first breadcrumb. Do not require `scopes` on that line.
- On a store-hit remediation, call `logger.Trace` with stem `ServeHTTP`, `ip`, `remediation`, and `withPresentScopes` from the map already in `scopes`. Do not pass `cache`.
- On a remediating `LiveLookup`, keep stem `ServeHTTP:LiveLookup`, `ip`, and `isBanned`. Attach the same `scopes` group. Do not pass `cache`.
- Reuse `GetRemoteIP` / `clientRequest.remoteIP` and the trusted-client `ContainsIP` result. Do not re-parse `RemoteAddr`. Do not call `RequestScopeValues` again at log time.
- Leave `handleRemediationServeHTTP` TRACE as `ip` + `remediation`. Leave DEBUG `ServeHTTP:Get` `cache` (the lookup error).
- Keep the first-breadcrumb stem recognizable. Do not drop `ip` or `isTrusted` from that line.
- Leave construct-time, stream-tick, and failure Debug (`Bouncer initialized`, `handleStreamCache:updated`, drain/parse errors) at Debug. Identity for those lines is on the constructor `log.With` child (`std_go_logger_nested`).
- On `bouncer.New` DEBUG `Bouncer initialized`, pass `forwardedHeadersTrustedIPs` and `clientTrustedIPs` from the Config slices as written. Bare hosts stay bare. Empty or nil slices still log both attrs as empty lists. Do not re-derive hops or client IP. Do not merge the two pools. Do not emit per-entry Checker insert Debug.
- Do not change default `logLevel` or file/format (`std_go_logger_slog-output`). Set `logLevel: TRACE` to see per-request breadcrumbs.

## Pattern snippet

```go
b.log.Debug("Bouncer initialized",
	"forwardedHeadersTrustedIPs", forwardedHeadersTrustedIPs,
	"clientTrustedIPs", clientTrustedIPs)
logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)
logger.Trace(b.log, "ServeHTTP", withPresentScopes([]any{"ip", req.remoteIP, "remediation", kind}, scopes)...)
logger.Trace(b.log, "ServeHTTP:LiveLookup", withPresentScopes([]any{"ip", req.remoteIP, "isBanned", kind}, scopes)...)
b.log.Debug("ServeHTTP:Get", "ip", req.remoteIP, "cache", lookupErr)
```

## Key files

- `pkg/logger/logger.go` — `LevelTrace`, `Trace`, `ReplaceAttr` names
- `pkg/bouncer/bouncer.go` — construct-time DEBUG `Bouncer initialized`, `ServeHTTP` Trace, `withPresentScopes`

## Gotchas

- INFO and DEBUG already drop Trace records. A test that only asserts "INFO emits nothing" passes on DestBranch interpolated `Sprintf`. Assert TRACE `msg` is the stem and the fields are attributes.
- Raw slog JSON without this package's `ReplaceAttr` prints Trace as `DEBUG-4`. Product `NewWithFormat` prints `TRACE`.
- `Enabled` + `Sprintf` also skips INFO formatting but needs a `ctx` the hot path does not have. Prefer attributes.
- A drain or parse `error` attribute is a failure, not a breadcrumb. Keep those at Debug (closeBody stays Error).
- Map iteration is random. Sort CrowdSec scope names when building group `scopes` so TRACE and tests stay stable.
- A JSON sink prints the group as a nested `scopes` object. Assert keys inside that object.
- Omit the group when `RequestScopeValues` is empty. Do not pass an empty Attr.
- JSON slog prints a nil `[]string` as `null`. Pass empty slices for the trusted-IP attrs so empty lists stay lists.
