## Context

See `proposal.md` Why. Dest `ServeHTTP` and `cache.Client` Get/GetMany/Set/Delete call `fmt.Sprintf` then `slog.Debug` (`pkg/bouncer/bouncer.go`, `pkg/cache/cache.go`). `*slog.Logger.Debug` evaluates call-site arguments before `Enabled`. `logger.NewWithFormat` already sets `HandlerOptions.Level` (default INFO). Consume only.

FindSpecHost:

```
verdicts:
  - { deltaId: lazy-debug-hot-path, fold|new: new, spec-id: std_go_logger_debug-attrs, confidence: high, candidates: [std_go_logger_slog-output, core_plugin_middleware_bouncer, core_cache_client_decision-store, core_cache_client_isolated-store] }
```

Search: family `std_go_logger` leaf `slog-output` owns `NewWithFormat` destination and format. `core_plugin_middleware_bouncer` is Yaegi `New` / reclaim / config snapshot. Cache DecisionStore leaves own isolation and reclaim, not Debug formatting. Call-site Debug evaluation is a new capability, not a one–three-requirement bugfix of those leaves.

Identity: `GetRemoteIP` owns the client address; `ContainsIP` owns `isTrusted`. Reuse those values.

## Goals / Non-Goals

**Goals:**

- INFO request path does not build Debug format strings.
- DEBUG still logs the same fields as slog attributes with recognizable stems.
- Tests fail on DestBranch interpolated `msg=` and pass after attributes.

**Non-Goals:**

- Changing `NewWithFormat`, default `logLevel`, or file/format.
- Repo-wide Debug `Sprintf` (`cache.New`, `Acquire`, captcha, LAPI, AppSec).
- `handleRemediationServeHTTP` / AppSec Debug.
- A committed ns benchmark.

## Decisions

1. **slog attributes, not `Enabled` + `Sprintf`.** `log.Debug("ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)` and the same shape on cache Get/GetMany/Set/Delete. Alternative: `if log.Enabled(ctx, slog.LevelDebug) { log.Debug(fmt.Sprintf(...)) }` — rejected (needs a `ctx` the hot path does not have; attributes are the slog contract).
2. **Include Set/Delete** as `cache.Client` siblings. Leave `cache.New` (construct) and `Acquire` (stream lease).
3. **Include every Debug `Sprintf`/`+` in `ServeHTTP`** (cache err, cache hit, stream-unhealthy, LiveLookup) for Symmetry. Leave Error/Warn `Sprintf`. Leave `handleRemediationServeHTTP` and AppSec Debug.
4. **New spec leaf** `std_go_logger_debug-attrs`. Do not fold into `std_go_logger_slog-output`.
5. **Tests assert DEBUG attribute records**, not "INFO emits nothing" alone (DestBranch already drops Debug at INFO). Use the package log-sink helper when asserting output (`std_go_test_log-sink`). Add a sink in `pkg/cache` / `pkg/bouncer` if missing.

## Risks / Trade-offs

- [DEBUG `msg=` text changes from interpolated to stem + attributes] → Ticket allows recognizable text; operators grepping the old blob must switch to attribute keys.
- [Set/Delete are not on every stream allow] → Same type, same Debug pattern; leaving them would widen an asymmetry this change creates.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert.
