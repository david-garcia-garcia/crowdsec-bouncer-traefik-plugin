Title: Typed cache SetInt/GetInt and store-owned origin intern

Supersedes closed PR 99 (`pack-decision-origin`). That implementation put a remediation codec in pkg/cache (`Stored`, `Packed`, `Leftover`, `SetRemediation`, `GetManyStored`, `ParsePackedOriginID`, uint32 Get returning a kind letter, `\x1e` range-index encoding). That is the wrong domain.

Desired (memory RSS for stream/alone at ~400K IP decisions, no public config):

1. pkg/cache is a typed bag only. Keep Set/Get/GetMany/Delete/Acquire for strings. Add SetInt/GetInt (uint32 is enough) that store a machine word in the memory ttl_map. Redis Int may encode as decimal string or 4 bytes — opaque to callers. Cache MUST NOT know kind, origin, Packed, Stored, Remediation, or range-index separators. No SetRemediation. No MemoryBackend type switch for remediations.

2. Origin intern table stays on DecisionStore (append-only name→uint16, lock-free OriginName). Pack word is store/lapi: `uint32(kind[0]) | uint32(id)<<8`. Overflow keeps the existing leftover string path (`RemediationWithOrigin`). Table is not a package var. Not shared across DecisionStore reclaim keys.

3. decisionscope owns any range-index line encoding (letter or letter+id as a string). That blob uses cache Set, never SetInt. Lookup/bouncer: GetInt for packed memory IPs; on miss or leftover, Get string. Resolve origin name from the store table only on drop. No second lock on the allow-path GetInt.

4. Compact activeDecisionSlots to originID + family using the same store table. Keep the slot map (per-slot forget). Live/none may keep leftover strings. Redis may keep leftover strings.

5. Do not extract stream/live/metrics into new packages in this ticket (session hex would cycle if DecisionStore leaves lapi). Shrinking lapi is intern staying off Client except thin forwards if tests need them. Update knowledge/devdocs cache usage: do not put a remediation codec in pkg/cache; add typed get/set instead.

Out of scope: Redis intern table; replacing ttl_map; dropping activeDecisionSlots; new config; full lapi package split; reopening PR 99.
