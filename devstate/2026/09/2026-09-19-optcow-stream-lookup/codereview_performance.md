# Performance

1. [hard] Unbounded collection — `pkg/decisionstore/memory.go:85` — live `Put` (not ticking) writes `pubWord`/`pubExp` keyed by client IP and header-scope id; `LookupRemediation` treats `ExpiresAt` as a miss and leaves the slot; `PublishTick` only drops keys inside a stream window (`client.go` `startStream` never opens one in live)
   → Drop expired live slots on the memory engine (sweep on Put or delete-on-read) so unique-IP keys cannot accumulate past TTL
   Status: done
   Argument: f92c8573 putPublishedLocked sweeps expired pubExp keys before write.
2. [hard] Hot-path full scan or compile — `pkg/decisionstore/memory.go:105` — `putPublishedLocked` clones both published maps on every live `Put` (`memoLive` after a cache miss); work is O(unique IPs already stored) on the request path
   → Mutate published maps in place under `mu` and hold `RLock` across the lookup probes, or clone once per batch, not per IP
   Status: done
   Argument: f92c8573 live Put mutates pub maps in place; LookupRemediation holds RLock across probes.
