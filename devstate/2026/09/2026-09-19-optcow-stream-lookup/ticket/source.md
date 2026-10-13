# Stream/alone in-memory copy-on-write IP snapshot for request lookup

In-memory stream/alone only. Do not change Redis. Live/none stay on the TTL map.

Ship OptCOW: on the stream tick, publish one immutable snapshot (packed IP/header words as map[string]uint32, plus the existing Range membership snapshot) via atomic.Value — same cadence as hydrateRangeMembership. ServeHTTP Load()s that snapshot. Lookup is one map probe, no leftover GetMany on the packed memory path, skip Range when the IP slot is already ban. Range Contains must not take an exclusive mutex on an immutable snapshot. TTL is not write-on-Get; drop expired IP slots on the same tick that publishes. Do not clone the map per stream Set; publish once per tick. The snapshot replaces the TTL map as the request-path IP store for stream/alone memory — do not keep both copies of the same IPs.

Header-mapped scopes stay keys on the same snapshot map (not a radix). Ban still wins across Ip, Range, and headers.

The delivery card MUST include measured numbers vs origin/main proving the change improves (1) retained heap, (2) allocs/op on lookup, (3) throughput (ns/op sequential and parallel miss). Include a short why for each (ttl_map Data vs map[string]uint32; leftoverKeys+GetMany+To16+exclusive Range lock; Get-can-Del vs lock-free Load).

Out of scope: path-compressed Patricia combining IPs and ranges; Redis; live negative-cache COW; stuffing IPs into the uncompressed Helper as /32s.
