## 1. Typed cache bag

- [x] 1.1 Add `SetInt`/`GetInt` (`uint32`) on `cache.Client` and both backends. Memory stores a machine word in `ttl_map`. Redis encodes decimal ASCII through existing `Set`/`Get` `[]byte`.
- [x] 1.2 `GetInt` returns `CacheMiss` when the key is absent or the stored value is not that word (including a leftover string).
- [x] 1.3 Do not add Packed, Stored, Leftover, SetRemediation, GetManyStored, ParsePackedOriginID, MemoryBackend, or `\x1e` in `pkg/cache`.

## 2. Leftover helpers leave cache

- [x] 2.1 Move `RemediationKind`, `RemediationOrigin`, and `RemediationWithOrigin` to `pkg/decisionscope`. Delete `pkg/cache/remediation.go`.
- [x] 2.2 Update callers in `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`, and tests to the new owner.

## 3. DecisionStore intern and pack

- [x] 3.1 Add append-only name→`uint16` intern and lock-free `OriginName` on `DecisionStore`. Not a package var. Not shared across reclaim keys.
- [x] 3.2 Pack word is `uint32(kind[0]) | uint32(id)<<8`. Overflow keeps leftover strings. Intern stays off `Client` except thin forwards tests need.
- [x] 3.3 Stream/alone memory Ip and header writes intern, pack, and `SetInt`. Redis, live/none, and overflow use leftover `Set`.

## 4. Range-index and lookup

- [x] 4.1 `decisionscope` encodes packed range-index lines as letter plus decimal intern id. Leftover stays letter + U+001F + origin. Blob uses `Set`, never `SetInt`.
- [x] 4.2 Lookup tries `GetInt` then `Get`. Resolve `OriginName` only on drop. Allow-path `GetInt` has no second intern lock. Client address stays `pkg/ip.GetRemoteIP`.

## 5. Compact slots and usage docs

- [x] 5.1 Compact `activeDecisionSlots` to `originID` + family. Keep the slot map. POST still emits origin names via `OriginName`.
- [x] 5.2 Update `knowledge/devdocs/core_cache_client.md` (and Redis usage if Int encoding is documented): typed get/set; no remediation codec in `pkg/cache`.
- [x] 5.3 Add or update tests under `pkg/cache`, `pkg/lapi`, `pkg/decisionscope`, and `pkg/bouncer` for SetInt miss, packed memory write, leftover fallback, compact forget, and leftover Range-index.

## 6. Verify

- [x] 6.1 Run the existing package tests that cover cache, lapi, decisionscope, and bouncer. Do not extract stream/live/metrics packages.
