# Do not fmt.Sprintf before slog.Debug on the stream request path

Problem: Stream mode + in-memory cache allow path still builds debug strings on every request. ServeHTTP does log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", ...)) before the cache lookup. cache.Client.Get / GetMany / Set / Delete do the same. slog.Debug receives an already-built string, so INFO still pays Sprintf. Measured (compiled Go, logs to NUL): INFO allow 524 ns; DEBUG allow 2015 ns (4×). High-traffic proxies must not run logLevel DEBUG, but the INFO path still allocates those strings.

Desired: On the request hot path (bouncer ServeHTTP + cache Get/GetMany at minimum), do not evaluate fmt.Sprintf unless Debug is enabled. Use slog attributes (log.Debug("ServeHTTP", "ip", remoteIP, "isTrusted", isTrusted)) or Enabled(ctx, LevelDebug) before Sprintf. Behavior and message text can stay recognizable; do not drop fields. Do not change log levels, file/format config, or non-request-path Warn/Error formatting unless a sibling on the same hot function would otherwise stay inconsistent (commandments Symmetry).

Out of scope: Range radix origin, cache.ErrMiss, Redis, AppSec, replacing slog, changing default logLevel.

Key files: pkg/bouncer/bouncer.go ServeHTTP Debug lines, pkg/cache/cache.go Get/GetMany/Set/Delete Debug lines, pkg/logger/logger.go (consume only). Bound the ask to the request hot path; do not rewrite the whole repo's Sprintf-Debug calls unless they sit on that path.

Deployment constraint: stream mode + in-memory cache.
