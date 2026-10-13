# Explore
IssueKey: 2026-09-18-lazy-debug-log

## Concepts

Stream-mode allow is `ServeHTTP` → trusted-IP check → `LookupCachedRemediation` → `cache.Client.GetMany` → miss/none → `handleNextServeHTTP`. The first Debug line runs before the cache lookup. `Get`/`GetMany`/`Set`/`Delete` each `Sprintf` then `Debug` before the store call.

```
request
  │
  ▼
ServeHTTP
  GetRemoteIP → clientRequest.remoteIP / ipAddr
  ContainsIP  → isTrusted
  Debug(Sprintf("ServeHTTP ip:%s isTrusted:%v"))   ← always allocates
  │
  ├─ trusted → next (allow)
  └─ stream/live/alone
       LookupCachedRemediation
         GetMany(Sprintf("cache:GetMany keys:%v"))  ← always allocates
       cache hit / miss / stream-unhealthy / LiveLookup
         more Debug(Sprintf) on the same function
```

`logger.NewWithFormat` sets `HandlerOptions.Level` (default INFO). `*slog.Logger.Debug` still evaluates call-site arguments first; `Enabled` is inside the logger after `fmt.Sprintf` has already run. Passing existing values as slog attributes builds no format string on INFO. `Enabled(ctx, LevelDebug)` before `Sprintf` is the other allowed shape.

Identity already has owners. `GetRemoteIP` owns the client address. After a successful parse, `req.remoteIP` is `ipAddr.String()`. `clientPoolStrategy.Checker.ContainsIP` owns `isTrusted`. Debug lines reuse those values.

Existing spec `std_go_logger_slog-output` owns construct-time destination and format (`NewWithFormat`). This ticket is call-site Debug evaluation on the request path, not that leaf. Cache DecisionStore specs do not mention Debug formatting. No test asserts these Debug strings.

`cache.New` Debug is construct-time. `handleRemediationServeHTTP` / AppSec Debug run after an allow decision. Repo-wide `Sprintf`/concat Debug (`pkg/captcha`, `pkg/lapi`, `cache.Acquire`) is not this path.

Ticket ns numbers were not re-measured. The Sprintf-before-Debug call sites are on disk as claimed.

## Decisions

- Convert request-path Debug to slog attributes (`log.Debug("ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)`), not an `Enabled` + `Sprintf` guard. No extra `ctx`. Fields stay; message stems stay recognizable (`ServeHTTP`, `ServeHTTP:Get`, `cache:Get`, `cache:GetMany`).
- Include every `ServeHTTP` Debug `Sprintf` (and the LiveLookup `+` concat) for Symmetry on that function. Leave `Error`/`Warn` `Sprintf`. Leave `handleRemediationServeHTTP` and AppSec Debug (after the allow decision; AppSec out of scope).
- Include `cache.Client` Get, GetMany, Set, Delete as siblings (same Debug pattern on the same type). Leave `cache.New` (construct). Leave `Acquire` (stream lease, not every request).
- Do not change `pkg/logger` construct, default `logLevel`, file/format, or `std_go_logger_slog-output`.
- Do not rewrite repo-wide Debug `Sprintf`.
- Tests: INFO must not emit these Debug lines; DEBUG must still carry the same fields as slog attributes. Do not lock old interpolated `msg=` text.
- Spec: new call-site leaf under `std_go_logger_*` (or equivalent FindSpecHost fold). Do not extend `std_go_logger_slog-output` (that leaf is destination/format).
- No new Language this explore. Usage packets already name `GetRemoteIP`, `clientRequest`, and DecisionStore. Hot-path Debug style is propose/devdocsimpact if a usage gap remains.
- No slog research clone. Stdlib `Logger.Debug` evaluates args before `Enabled`; the ticket already states that. Go research index has no slog-args finding and implement does not need a clone.

## Open questions

- Q: Who already owns the client address and trusted-client flag that ServeHTTP Debug logs?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client address (`clientRequest.remoteIP` / `ipAddr` after `ipAddr.String()`). `clientPoolStrategy.Checker.ContainsIP` owns `isTrusted`. Reuse those outputs; do not re-parse `RemoteAddr` or the chosen string.
  By: explore

- Q: slog attributes or `Enabled` before `Sprintf` on the hot path?
  Decision: assumed — slog attributes. Same fields, recognizable message stems, no `ctx`, no format string on INFO.
  By: explore

- Q: Must Set/Delete change in the same apply (ticket names them; desired says Get/GetMany at minimum)?
  Decision: assumed — yes. They share the Debug `Sprintf` pattern on `cache.Client`. Leave `cache.New`.
  By: explore

- Q: Which other ServeHTTP Debug lines change for Symmetry?
  Decision: assumed — every Debug `Sprintf`/`+` in `ServeHTTP` (cache err, cache hit, stream-unhealthy, LiveLookup). Leave `handleRemediationServeHTTP` and AppSec Debug. Leave Error/Warn.
  By: explore

- Q: Re-measure ticket ns (INFO 524 / DEBUG 2015) before proposing?
  Decision: assumed — no. Call sites match. Implement adds tests that INFO does not emit Debug; do not require a committed benchmark.
  By: explore

- Q: Write a stdlib slog research folder?
  Decision: assumed — no. Evaluation-before-Enabled is stdlib; ticket already states it.
  By: explore
