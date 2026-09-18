# Standards

1. [hard] Name for the scope — `pkg/cache/cache.go:44` — `typed` drops the stem `value` on a type assert this body just did
   → Rename to `valueTyped`
   Status: done
   Argument: f7bd466 renamed `typed` to `valueTyped` in `localCache.get`.
2. [hard] Name for the scope — `pkg/cache/cache.go:89` — `typed` drops the stem `value` on a type assert this body just did
   → Rename to `valueTyped`
   Status: done
   Argument: f7bd466 renamed `typed` to `valueTyped` in `localCache.getStored`.
3. [hard] Name for the scope — `pkg/cache/cache.go:80` — `setValue` / `value` hide that the only caller stores a packed ttl_map word
   → Rename to `setPackedWord` and take `word uint32`
   Status: done
   Argument: f7bd466 renamed to `setPackedWord(key string, word uint32, duration int64)`.
4. [hard] Name for the scope — `pkg/cache/cache.go:296` — `raw` names GetMany’s producer form; this body only wraps leftovers
   → Rename to `leftovers`
   Status: done
   Argument: f7bd466 renamed GetMany result to `leftovers` in `GetManyStored`.
5. [hard] Name for the scope — `pkg/cache/stored.go:83` — `rest` hides the origin-id decimal the next line parses
   → Rename to `originIDText`
   Status: done
   Argument: f7bd466 renamed Cut remainder to `originIDText` in `ParseStored`.
6. [hard] Leave a trail — `pkg/cache/cache.go:80` — new `setValue` has no job comment
   → Add a succinct comment that this writes a packed word into ttl_map
   Status: done
   Argument: f7bd466 added job comment on `setPackedWord`.
7. [hard] Leave a trail — `pkg/cache/cache.go:84` — new `getStored` has no job comment
   → Add a succinct comment that this returns a packed or leftover Stored
   Status: done
   Argument: f7bd466 added job comment on `getStored`.
8. [hard] Name for the scope — `pkg/decisionscope/zzz_range_test.go:134` — `got` hides the Lookup kind that ServeHTTP and new tests name `kind`
   → Rename `got` to `kind` in the retargeted Lookup tests
   Status: done
   Argument: f7bd466 renamed Lookup result to `kind` in the three retargeted origin tests.
9. [hard] Name for the scope — `pkg/decisionscope/zzz_range_test.go:157` — `stored` is first the leftover index line, then the Lookup payload
   → Rename the leftover setup to `leftover`
   Status: done
   Argument: f7bd466 renamed range leftover setup to `leftover`.
10. [hard] Name for the scope — `pkg/decisionscope/zzz_packed_test.go:41` — `ok` hides the packed-origin-id flag siblings name `packed`
   → Rename to `packed`
   Status: done
   Argument: f7bd466 renamed ParsePackedOriginID flag to `packed`; setup Stored is `packedStored`.
11. [hard] Name for the scope — `pkg/cache/zzz_stored_test.go:11` — `ok` from PackedWord is the same packed flag this test names `packed` two lines later
   → Rename to `packed`
   Status: done
   Argument: f7bd466 renamed PackedWord flag to `packed`.
