# Request-path Trace attributes

## Language

**Request-path Trace**:
A Trace call on the request hot path (`ServeHTTP` allow/hit, captcha Check/Validate) that must not format a string unless the logger's level includes Trace.
_Avoid_: Sprintf-then-Trace, concatenating the message before `Trace`, logging per-request breadcrumbs at Debug, logging failures at Trace

## Overview

`slog.Logger` has no Trace method. Use `logger.Trace` (`slog.Level(-8)`). Call-site arguments are still evaluated before `Enabled`, so pass a message stem and the fields as slog attributes instead of `fmt.Sprintf`. DEBUG still covers construct-time, stream-tick, and request-path failure lines.

## How to use

- Call `logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)` (or cache-hit `remediation`).
- Reuse `GetRemoteIP` / `clientRequest.remoteIP` and the trusted-client `ContainsIP` result. Do not re-parse `RemoteAddr`.
- Keep the stem recognizable. Do not drop fields DestBranch already logged.
- Leave construct-time, stream-tick, and failure Debug (`Bouncer initialized`, `handleStreamCache:updated`, drain/parse errors) at Debug.
- Do not change default `logLevel` or file/format (`std_go_logger_slog-output`). Set `logLevel: TRACE` to see per-request breadcrumbs.

## Pattern snippet

```go
logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)
b.log.Debug("ServeHTTP:Get", "ip", req.remoteIP, "cache", lookupErr)
```

## Key files

- `pkg/logger/logger.go` — `LevelTrace`, `Trace`, `ReplaceAttr` names
- `pkg/bouncer/bouncer.go` — `ServeHTTP` Trace

## Gotchas

- INFO and DEBUG already drop Trace records. A test that only asserts "INFO emits nothing" passes on DestBranch interpolated `Sprintf`. Assert TRACE `msg` is the stem and the fields are attributes.
- Raw slog JSON without this package's `ReplaceAttr` prints Trace as `DEBUG-4`. Product `NewWithFormat` prints `TRACE`.
- `Enabled` + `Sprintf` also skips INFO formatting but needs a `ctx` the hot path does not have. Prefer attributes.
- A drain or parse `error` attribute is a failure, not a breadcrumb. Keep those at Debug (closeBody stays Error).
