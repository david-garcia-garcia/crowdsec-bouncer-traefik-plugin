# Standards

Fixed point: `origin/master` = `15e65c9fe1de4a96530b2e443b59d90338b43897`. Reviewed `origin/master...HEAD` excluding `devstate/` and `.cursor/`.

1. [hard] Leave a trail — `pkg/health/tracker.go:47` — new private method `log()` has no succinct job comment
   ```go
   func (ht *Tracker) log() *slog.Logger {
   	if ht.logger != nil {
   		return ht.logger
   	}
   	return slog.Default()
   }
   ```
   → Add a one-line comment stating it returns the injected logger or the default.
   Status: done
   Argument: added job comment on Tracker.log() (`cfdb46f`).

2. [judgement] Smallest durable delta — `pkg/configuration/configuration.go:179` — `New()` struct literal re-aligned for every field when only six backoff knobs were added
   ```go
   	return &Config{
-		Enabled:                         false,
+		Enabled:                             false,
 		LogLevel:                            LogINFO,
 		...
 		AppsecFailureBackoffTimeout:         30,
 		...
-		RedisCacheUnreachableBlock:      true,
+		RedisCacheUnreachableBlock:          true,
   	}
   ```
   Same column-alignment churn appears in `pkg/lapi/identity.go` and `pkg/appsec/session.go` identity structs. → Limit edits to the new backoff fields; leave sibling field alignment unchanged.
   Status: skipped
   Argument: judgement; gofmt column alignment of the updated literals is the durable form; undoing sibling spacing is extra churn.

3. [judgement] Symmetry and consistency — `pkg/health/tracker.go:15` — public API and logs use *unhealthy* / *backoff* while internal state fields use *shutdown*
   ```go
   isShutdown       atomic.Bool // lockless fast path for IsUnhealthy()
   shutdownUntil    time.Time
   ...
   ht.log().Warn("marking backend as unhealthy", ...)
   ...
   func (ht *Tracker) IsUnhealthy() bool {
   	if !ht.isShutdown.Load() {
   ```
   → Rename internal fields to match the unhealthy/backoff vocabulary (`isUnhealthy`, `unhealthyUntil`) or document the sister-name mapping once at the type level.
   Status: skipped
   Argument: judgement; field names copied from the sister traefik-modsecurity Tracker; renaming would diverge without a production need.
