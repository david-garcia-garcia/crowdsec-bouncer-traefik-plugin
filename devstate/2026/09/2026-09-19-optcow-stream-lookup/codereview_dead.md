# Dead

1. [hard] Test-only new symbol — `pkg/decisionstore/pack.go:17` — `Pack` / `OriginIntern` / `originIntern` have no production callers after memory packing moved to `memory.pack`. `git grep Pack( HEAD -- "*.go"` hits the definition plus `zzz_pack_test.go`, `zzz_lookup_test.go`, `zzz_lookup_bench_test.go` only. `git grep originIntern` / `OriginIntern` HEAD: `store.go:117` definition and those tests (`testOriginIntern` in `zzz_pack_test.go`). Runtime encode is `memory.pack` → `intern.Table.ID` + `packWord`; Redis uses `KindOriginString`. `git grep pkg/cache HEAD -- "*.go"` is empty
   → Delete `Pack`, `OriginIntern`, and `originIntern`; assert packed words via `packWord` after `intern.Table.ID`, or through `Store.Put` / `LookupRemediation`
   Status: done
   Argument: f92c8573 deleted Pack, OriginIntern, originIntern; tests use packWord + intern.Table.ID.
