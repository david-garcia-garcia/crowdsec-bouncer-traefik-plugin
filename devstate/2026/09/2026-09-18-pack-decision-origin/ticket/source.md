Title: Pack stream-mode decision origin in the in-memory cache

Reduce Traefik RSS for stream/alone in-memory decision storage at ~400K IP decisions. Today each decision stores a full usage-metrics origin string twice: once in the ttl_map cache value via `cache.RemediationWithOrigin` (`kind + 0x1F + origin`), and once in `MetricsReporter.activeDecisionSlots` as `usageMetricKey` (five string headers, origin unique per json.Unmarshal).

Desired:
- Build an origin dictionary on the fly (append-only). First time a `MetricsOrigin` string is seen, assign the next numeric id. Reverse map on the stream write path. Kind letters (`t`/`c`/`f`/`d`) stay raw ASCII bytes — no kind dictionary. `ip_type` may be a byte (`4`/`6`).
- Pack the in-memory cache value as kind byte + origin id (not a per-decision origin string). Request path extracts kind by shift/mask; resolve `table[id]` only when reporting a drop. Do not add a second lock on `cache.Get`. Intern table is append-only so reads can be lock-free.
- Compact `activeDecisionSlots` the same way (`originID` + family), because that map is larger than the TTL map (~66 MiB vs ~52 MiB at 400K in a heap probe). That is in-scope — it is the same origin table, not a separate product.
- Table lives on the DecisionStore / MetricsReporter reclaim value for that LAPI session. Not a package `var`. Not shared across sessions.
- Redis is out of scope for this worry: the Redis backend may keep writing the full origin string. Do not require a shared Redis intern table. Memory path may differ from Redis behind `cacheInterface`.
- Do not replace ttl_map / custom IP-as-bytes maps in this ticket (larger Yaegi-sensitive change). Do not drop `activeDecisionSlots` entirely (need per-slot forget).
- No new public config surface.

Measured (explore probe, CAPI-like mix, 400K IPv4): current ~113 MiB; intern-only ~96 MiB; packed cache + compact slots ~54 MiB. Operator cares about in-memory RSS, not Redis payload size.
