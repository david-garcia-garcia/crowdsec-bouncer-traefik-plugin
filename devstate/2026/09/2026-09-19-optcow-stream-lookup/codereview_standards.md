# Standards

1. [hard] Name for the scope — `pkg/bouncer/bouncer.go:198` — `value` is the LookupRemediation kind; the LiveLookup sibling in this same body already names that role `kind`
   → Rename the LookupRemediation result to `kind`
   Status: done
   Argument: applied in f92c8573.
2. [hard] Name for the scope — `pkg/bouncer/bouncer.go:200` — `cacheErr` is the DecisionStore lookup error this body matches with `decisionstore.ErrMiss` / `ErrUnreachable`
   → Rename to `lookupErr`
   Status: done
   Argument: applied in f92c8573.
3. [hard] Name for the scope — `pkg/decisionstore/store.go:88` — `cachePrefix` is passed only as NewRedis `keyPrefix` (`Open` comment: Redis key prefix)
   → Rename the parameter to `keyPrefix`
   Status: done
   Argument: applied in f92c8573.
4. [hard] Name for the scope — `pkg/decisionstore/store.go:109` — `store, ok := stored.(*Store)` drops stem `stored` on a type assert this body just did
   → Keep the stem: `storedTyped, ok := stored.(*Store)`
   Status: done
   Argument: applied in f92c8573.
5. [hard] Name for the scope — `pkg/decisionstore/store.go:181` — `membership, _ := stored.(*RangeMembership)` assigns a second domain name after `stored := s.rangeMembership.Load()`
   → Name the Load result `membership` and the assert `membershipTyped`
   Status: done
   Argument: applied in f92c8573.
6. [hard] Name for the scope — `pkg/decisionstore/pack.go:31` — `switch stored := payload.(type)` drops stem `payload` on the type switch this body just did
   → Rename to `payloadTyped`
   Status: done
   Argument: applied in f92c8573.
7. [hard] Name for the scope — `pkg/decisionstore/lookup.go:34` — `stored, isString := payload.(string)` drops stem `payload` on a type assert this body just did
   → Keep the stem: `payloadTyped, isString := payload.(string)`
   Status: done
   Argument: applied in f92c8573.
8. [hard] Name for the scope — `pkg/decisionstore/lookup.go:43` — `get` is a vague verb; this body uses the callback as the slot payload for a key
   → Rename to `payloadForKey`
   Status: done
   Argument: applied in f92c8573.
9. [hard] Name for the scope — `pkg/lapi/client_decisions.go:183` — `parsedDuration` names how the producer got the TTL; `liveCacheTTL` only converts it to seconds (`ipResult.duration` / `result.duration` at the call sites)
   → Rename the parameter to `duration`
   Status: done
   Argument: applied in f92c8573.
10. [hard] Name for the scope — `pkg/lapi/client_decisions.go:92` — `value := decisionscope.RemediationValue(picked.Type)` is stored as `liveResult.kind`
    → Rename to `kind`
    Status: done
    Argument: applied in f92c8573.
11. [hard] Name for the scope — `pkg/lapi/client_decisions.go:26` — `value := decisionscope.RemediationValue(item.Type)` is passed as `Decision.Kind`
    → Rename to `kind`
    Status: done
    Argument: applied in f92c8573.
12. [hard] Name for the scope — `pkg/lapi/client_stream.go:121` — `value := decisionscope.RemediationValue(decision.Type)` is the Range blob kind (`KindOriginString(value, origin)`)
    → Rename to `kind`
    Status: done
    Argument: applied in f92c8573.
13. [hard] Name for the scope — `pkg/decisionstore/redis.go:32` — `backend` is the leftover dispatch nickname; this body constructs a `*redis`
    → Name it `red` (same role as `redisEngine` / `Store.red`)
    Status: done
    Argument: applied in f92c8573.
14. [hard] Name for the scope — `pkg/decisionstore/memory.go:241` — `packed` is the producer’s pack suffix; `cloneUint32Map` only copies the word (`LiveSlot.Word`, `putTick`)
    → Rename the range value to `word`
    Status: done
    Argument: applied in f92c8573.
15. [hard] Name for the scope — `pkg/decisionstore/redis.go:108` — `logical` hides the unprefixed slot keys the next lines join to MGET results
    → Rename to `slotKeys`
    Status: done
    Argument: applied in f92c8573.
16. [hard] Name for the scope — `pkg/decisionstore/memory.go:137` — `legacy` hides the prior Ip spelling `slotKeys` returns for delete (`key, legacy := slotKeys(...)`; same at `redis.go:183`)
    → Rename to `priorSpelling`
    Status: done
    Argument: applied in f92c8573.
17. [hard] Name for the scope — `pkg/decisionstore/decision.go:56` — `IPCacheKey` is the Ip slot key; sibling `HeaderScopeKey` does not say cache
    → Rename to `IPSlotKey`
    Status: skipped
    Argument: ticket pin keeps IPCacheKey; do not rename.
18. [hard] Name for the scope — `pkg/decisionstore/zzz_lookup_test.go:13` — `got` hides the lookupHits kind that `TestLookupHitsMiss` names `kind` (same `got` at `:28`, `:35`, `:43`, `:61`, `:69`, `:77`, `:84`)
    → Rename every lookupHits kind result in this file to `kind`
    Status: done
    Argument: applied in f92c8573.
19. [hard] Name for the scope — `pkg/decisionstore/zzz_lookup_test.go:61` — `gotID` drops the stem `originID` that `TestLookupHitsMiss` uses
    → Rename to `originID`
    Status: done
    Argument: f92c8573 renamed to unpackedID; originID is already the interned id in that test.
20. [hard] Name for the scope — `pkg/lapi/zzz_ipcachekey_test.go:34` — `value, _, _, err := client.LookupRemediation(...)` is the kind ServeHTTP’s live path names `kind`
    → Rename to `kind`
    Status: done
    Argument: applied in f92c8573.
21. [hard] Leave a trail — `pkg/bouncer/bouncer.go:218` — edited comment says “allow-path intern Name is lock-free”; `intern.Table.Name` now takes `RLock` (`pkg/intern/table.go:60`) and this path only skips `OriginName` on allow
    → Say origin is resolved only on drop; do not claim Name is lock-free
    Status: done
    Argument: applied in f92c8573.
22. [hard] Leave a trail — `pkg/decisionstore/memory.go:124` — intern-overflow Warn has `kind` but not the `origin` this body already interned
    → Attach `"origin", origin` on the Warn
    Status: done
    Argument: applied in f92c8573.
23. [hard] Leave a trail — `pkg/lapi/client_decisions.go:24` — new `storeStreamDecision` comment says “into the cache”; the body is `decisionStore.Put`
    → Comment that this Puts one non-Range stream decision
    Status: done
    Argument: applied in f92c8573.
24. [hard] Leave a trail — `pkg/lapi/client_decisions.go:51` — new `deleteStreamDecision` comment says “from the cache”; the body is `decisionStore.Delete`
    → Comment that this Deletes one non-Range stream decision
    Status: done
    Argument: applied in f92c8573.
25. [hard] Leave a trail — `pkg/lapi/client.go:183` — `Sleep` still says it keeps “cache”; sibling `Close` (edited this change) says it does not Close the shared DecisionStore
    → Name the DecisionStore, not cache
    Status: done
    Argument: applied in f92c8573.
26. [hard] Leave a trail — `pkg/lapi/client.go:203` — `Wake` still says “the cache is still warm” after stream slots moved onto DecisionStore
    → Say the DecisionStore is still warm
    Status: done
    Argument: applied in f92c8573.
27. [hard] Leave a trail — `pkg/decisionstore/memory.go:12` — new type `memory` has no job comment; sibling `redis` does
    → Comment that this is in-process COW tick/published maps plus the Range blob
    Status: done
    Argument: applied in f92c8573.
28. [hard] Leave a trail — `pkg/decisionstore/store.go:31` — new `memoryEngine` has no job comment
    → Comment that this binds `*memory` methods into `engine` funcs
    Status: done
    Argument: applied in f92c8573.
29. [hard] Leave a trail — `pkg/decisionstore/store.go:44` — new `redisEngine` has no job comment
    → Comment that this binds `*redis` methods into `engine` funcs
    Status: done
    Argument: applied in f92c8573.
30. [hard] Leave a trail — `pkg/decisionstore/memory.go:24` — new `newMemory` has no job comment
    → Comment that this allocates non-nil tick/published maps
    Status: done
    Argument: applied in f92c8573.
31. [hard] Leave a trail — `pkg/decisionstore/redis.go:31` — new `newRedis` has no job comment
    → Comment that this dials the writer and optional readers via `simpleredis.New`
    Status: done
    Argument: applied in f92c8573.
32. [hard] Leave a trail — `pkg/decisionstore/redis.go:85` — new `get` has no job comment; sibling `set` does
    → Comment that this GETs one prefixed key from `nextReader` only
    Status: done
    Argument: applied in f92c8573.
33. [hard] Leave a trail — `pkg/decisionstore/redis.go:107` — new `getMany` has no job comment
    → Comment that this MGETs slot keys from `nextReader` only
    Status: done
    Argument: applied in f92c8573.
34. [hard] Leave a trail — `pkg/decisionstore/redis.go:151` — new `deleteKey` has no job comment; sibling `set` does
    → Comment that this DELs one prefixed key on the writer and is void
    Status: done
    Argument: applied in f92c8573.
35. [judgement] Speculative Generality — `pkg/decisionstore/lookup.go:44` — `if get == nil { get = func(string) any { return nil } }` has no production or test caller that passes nil
    → Drop the nil branch; require a payload callback
    Status: skipped
    Argument: judgement; nil payload callback stays defensive.
36. [judgement] Mysterious Name — `pkg/decisionstore/liveslot.go:9` — `Word` is the packed uint32; readers must open `pack.go` to know
    → Rename the field to `PackedWord`
    Status: skipped
    Argument: judgement; Word stays the packed uint32 field name.
