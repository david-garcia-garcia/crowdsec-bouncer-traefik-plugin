# Performance

1. [judgement] Unbounded collection or cache — `pkg/ratelimit/client.go:113` — default buffered mode (`rateLimitSyncRate` 200ms) keeps one vendored `windowcounter` `windows` entry per unique counter key (`limiter.go:36`, `limiter.go:296`), dropped only once 2×window has passed; there is no size cap, `compileWindow` (`pkg/ratelimit/bucket_set.go:133`) sets no upper bound on `window`, and a `header`/`cookie`/`query` key part lets a client mint a new entry (plus two Redis GETs) on every request; every flush tick (each syncRate) ranges the whole map twice under the mutex every `Take` needs (`limiter.go:427`, `limiter.go:471`), so memory and per-tick lock hold time grow with unique keys × window
   Fix: Cap `window` in `compileWindow` and document per-unique-key memory next to client-controlled key parts; record the missing size cap in the utilities-bump debt note
   Status: skipped
   Argument: judgement: windows expire after 2x window and the map lives in vendored `windowcounter` (not patched); a window cap is a product limit not asked for. README limits already warn that client-controlled key parts create one key per value.
2. [judgement] Per-request log I/O on a growing path — `pkg/bouncer/bouncer_serve_ratelimit.go:34` — one INFO line per over-limit request per `log` bucket, so log volume grows with exactly the client traffic the bucket observes; design §14 rejects WARN per request for this same client-driven-volume reason
   Fix: Log the first over-limit hit per bucket and key per window at INFO and the rest at DEBUG (needs the buckets spec line 61/77 changed), or keep it and document the volume
   Status: skipped
   Argument: judgement: INFO per over-limit request on a `log` bucket is what the buckets spec asks for; changing it needs a spec change.
3. [judgement] Redis round trips per request understated — `README.md:914` — exact mode (`rateLimitSyncRate: 0`) runs INCR, then GET of the previous window, plus EXPIRE on a key's first hit (`limiter.go:163`, `limiter.go:168`, `limiter.go:172`), for each matching bucket in series (`pkg/ratelimit/charge.go:56`), all in one 250ms budget; the README says one round trip per counted request
   Fix: Say two Redis round trips per charged bucket (three on a key's first hit in a window), run in series
   Status: done
   Argument: README exact-mode line now says two Redis round trips per counted bucket (three on a counter's first hit in a window), one bucket after another.
