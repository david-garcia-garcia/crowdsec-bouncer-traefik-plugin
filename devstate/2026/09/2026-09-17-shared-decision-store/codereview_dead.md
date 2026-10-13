# Dead

1. [hard] Leftover production path — `pkg/lapi/session.go:145` — `CachePrefix` now only returns `SessionHex(cfg)`; `OpenDecisionStore` already passes `SessionHex(cfg)` to `cache.Client.New`. Grep `CachePrefix`: definition in `session.go` only; remaining hits are `zzz_decisionstore_test.go` and `zzz_session_test.go` (docs/openspec/devstate ignored).
   → Delete `CachePrefix`; assert prefix via `SessionHex(cfg)`
   Status: done
   Argument: deleted CachePrefix; session/store tests assert SessionHex.

2. [hard] Exported wrapper with no runtime import — `pkg/lapi/decisionstore.go:62` — `AcquireLease` only forwards to `s.cache.Acquire(ctx, cacheTimeoutKey, value, duration)`. Production already calls the inner one: `c.Cache().Acquire(...)` in `pkg/lapi/client_stream.go:73`. Grep `AcquireLease`: definition only; no test callers.
   → Delete `AcquireLease`; assert the lease via `store.Cache().Acquire` or `handleStreamCache`
   Status: done
   Argument: deleted AcquireLease; lease stays on cache.Client.Acquire.
