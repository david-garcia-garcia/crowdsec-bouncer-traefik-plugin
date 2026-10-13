# Requirement
IssueKey: 2026-09-18-lazy-debug-log

## Problem
Stream mode + in-memory cache still builds debug strings on every allow. `ServeHTTP` and `cache.Client` Get/GetMany/Set/Delete call `fmt.Sprintf` and pass the result to `slog.Debug`. INFO still pays that allocation. Ticket measure (compiled Go, logs to NUL): INFO allow 524 ns; DEBUG allow 2015 ns.

## Current (code)
- `ServeHTTP` always `Sprintf`s `ServeHTTP ip:%s isTrusted:%v` then `Debug`s the string, before the cache lookup. `pkg/bouncer/bouncer.go`
- Same function later `Sprintf`s Debug on cache error, cache hit, stream-unhealthy, and LiveLookup. `pkg/bouncer/bouncer.go`
- `handleRemediationServeHTTP` and `applyAppsecServeHTTP` also `Sprintf` then Debug. `pkg/bouncer/bouncer.go`
- Stream/live/alone consult the cache via `LookupCachedRemediation` → `GetMany`. `pkg/decisionscope/lookup.go` `pkg/bouncer/bouncer.go`
- `cache.Client` Get, GetMany, Set, Delete each `Sprintf` then Debug before the store call. `pkg/cache/cache.go`
- `cache.Client` New also `Sprintf`s a Debug line at construct time. `pkg/cache/cache.go`
- `logger.NewWithFormat` builds a `*slog.Logger` with `HandlerOptions.Level` from `logLevel` (default INFO). It does not wrap `Debug`, so a call-site `Sprintf` always runs. `pkg/logger/logger.go`
- No test asserts these Debug message strings. not found

## Desired
- On the request hot path (`ServeHTTP` + cache Get/GetMany at minimum), do not evaluate `fmt.Sprintf` unless Debug is enabled.
- Use slog attributes (`log.Debug("ServeHTTP", "ip", remoteIP, "isTrusted", isTrusted)`) or `Enabled(ctx, LevelDebug)` before `Sprintf`.
- Keep the fields. Message text can stay recognizable.
- Do not change log levels, file/format config, or non-request-path Warn/Error formatting unless a sibling on the same hot function would otherwise stay inconsistent (Symmetry).

## Affected
- `pkg/bouncer/bouncer.go` (`ServeHTTP` Debug lines; other Debug on that function for Symmetry)
- `pkg/cache/cache.go` (Get/GetMany at minimum; Set/Delete if treated as siblings)
- `pkg/logger/logger.go` (consume only)

## Out of scope
- Range radix origin, `cache.ErrMiss` / `CacheMiss` semantics, Redis store, AppSec
- Replacing slog, changing default `logLevel`, logger file/format
- Repo-wide `Sprintf`-before-Debug (`pkg/captcha`, `pkg/ip`, `pkg/lapi` metrics, `cache.New`) unless they sit on this request path
- `handleRemediationServeHTTP` / `applyAppsecServeHTTP` Debug unless implement treats them as the same hot path

## Unknowns
- Ticket ns numbers were not re-measured this prepare.
- Whether implement uses slog attributes or an `Enabled` guard (ticket allows either).
- Whether Set/Delete must change in the same apply (ticket names them; desired says Get/GetMany at minimum).

## Tensions
- Ticket names Set/Delete as current cost and says Get/GetMany at minimum. Symmetry on `cache.Client` would include Set/Delete; Bound the ask would leave them if they are not on the stream allow path (stream apply, not every request).
- Ticket deployment is stream + in-memory allow. `ServeHTTP` also `Sprintf`s Debug on LiveLookup and stream-unhealthy; those are siblings on the same function.
- AppSec Debug is on the request path after allow and is listed out of scope.
- `cache.New` Debug is the same Sprintf pattern and is not a request-path call.
