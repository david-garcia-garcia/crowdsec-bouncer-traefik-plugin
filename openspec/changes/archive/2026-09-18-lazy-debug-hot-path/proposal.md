## Why

On DestBranch, stream-mode allow still builds debug strings on every request: `ServeHTTP` and `cache.Client` Get/GetMany/Set/Delete call `fmt.Sprintf` and pass the result to `slog.Debug`. INFO still pays that allocation. High-traffic proxies must not run `logLevel` DEBUG, but the INFO path still formats those strings.

## What Changes

- On the request hot path (`ServeHTTP` Debug lines and `cache.Client` Get/GetMany/Set/Delete), pass slog attributes instead of `fmt.Sprintf` so INFO does not format a debug string.
- Keep the same fields. Message stems stay recognizable (`ServeHTTP`, `cache:Get`, `cache:GetMany`). Reuse `clientRequest.remoteIP` and `isTrusted` already owned by `GetRemoteIP` / `ContainsIP`.
- Add tests that default INFO does not emit those Debug lines and DEBUG still carries the fields.
- Do not change log levels, logger file/format, `std_go_logger_slog-output`, `cache.New`, AppSec/remediation Debug, or repo-wide Debug `Sprintf`.

## Capabilities

### New Capabilities

- `std_go_logger_debug-attrs`: request-path Debug uses slog attributes (or an Enabled guard) so `fmt.Sprintf` does not run unless Debug is enabled.

### Modified Capabilities

None.

## Impact

- `pkg/bouncer/bouncer.go` (`ServeHTTP` Debug lines)
- `pkg/cache/cache.go` (Get/GetMany/Set/Delete Debug lines)
- Tests next to those packages
- `pkg/logger/logger.go` consume only (no construct change)
- No **BREAKING** public JSON/YAML keys
- Out of scope: Range radix, `cache.ErrMiss`, Redis store, AppSec, replacing slog, default `logLevel`, logger file/format, `cache.New`, `cache.Acquire`, `handleRemediationServeHTTP` / AppSec Debug
