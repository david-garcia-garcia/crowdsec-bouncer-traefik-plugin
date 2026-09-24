## Why

`storeBinding` mutates `Box.Value` in place after the first publish while concurrent `ServeHTTP` paths `Unbox` the same `*reclaim.Box`. That races: a torn `any` can panic the request, or a request can see a nil/stale client and take the wrong failure action or LAPI mode. Finding 1 only: publish a new immutable Box on every bind update.

## What Changes

- Change `storeBinding` so every update does `dest.Store(&reclaim.Box{Value: value})`; never assign `boxed.Value` in place.
- Keep the stored concrete type `*reclaim.Box` (Yaegi). Leave `Unbox` / `Watch` / `Published` unchanged.
- Companion: fix test helper `watchInto` in `pkg/reclaim/zzz_alias_test.go` to the same Store-new-Box publish shape (see `deviations.md`).
- Prove with a focused concurrent Unbox-vs-Store test where `go test -race` is available (cgo).
- Do **not** take Findings 2 or 3; no unrelated bouncer policy refactors.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: Late-bind requirement gains an immutable Box publish shape (Store a new `*reclaim.Box` on every subscriber update; no in-place `Box.Value` mutation). Load-only ServeHTTP, nil failure-action, and mode-from-published-client stay.

## Impact

- `pkg/bouncer/bouncer.go` (`storeBinding`; Receive* callers stay as feeders).
- `pkg/reclaim/zzz_alias_test.go` (`watchInto` only).
- Live contract delta under `core_plugin_middleware_bouncer`. Usage packets already document the Gotcha (`core_plugin_middleware_instance-slots`, `std_go_reclaim`); implement / devdocsimpact verify, do not invent a second leaf.
