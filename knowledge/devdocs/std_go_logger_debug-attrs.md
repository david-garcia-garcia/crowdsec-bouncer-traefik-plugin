# Request-path Debug attributes

## Language

**Request-path Debug**:
A Debug call on the request hot path (`ServeHTTP` or DecisionStore lookup) that must not format a string unless the logger's level includes Debug.
_Avoid_: Sprintf-then-Debug, concatenating the message before `Debug`

## Overview

`slog.Logger.Debug` evaluates call-site arguments before `Enabled`. Passing `fmt.Sprintf(...)` as the message makes INFO pay the format. Pass a message stem and the fields as slog attributes instead.

## How to use

- Call `log.Debug("ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)` (or `ServeHTTP:Get` + lookup error).
- Reuse `GetRemoteIP` / `clientRequest.remoteIP` and the trusted-client `ContainsIP` result. Do not re-parse `RemoteAddr`.
- Keep the stem recognizable. Do not drop fields DestBranch already logged.
- Leave construct-time Store Open, AppSec, and remediation Debug unless they sit on this path.
- Do not change `NewWithFormat`, default `logLevel`, or file/format (`std_go_logger_slog-output`).

## Pattern snippet

```go
b.log.Debug("ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)
b.log.Debug("ServeHTTP:Get", "ip", req.remoteIP, "cache", lookupErr)
```

## Key files

- `pkg/bouncer/bouncer.go` — `ServeHTTP` Debug
- `pkg/logger/logger.go` — consume only (`HandlerOptions.Level`)

## Gotchas

- INFO already drops Debug records. A test that only asserts "INFO emits nothing" passes on DestBranch interpolated `Sprintf`. Assert DEBUG `msg` is the stem and the fields are attributes.
- `Enabled` + `Sprintf` also skips INFO formatting but needs a `ctx` the hot path does not have. Prefer attributes.
