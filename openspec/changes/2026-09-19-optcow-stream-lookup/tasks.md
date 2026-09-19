## 1. Live map on DecisionStore

- [x] 1.1 Add `liveSlot` and `atomic.Value` holder on `DecisionStore` (reclaim-bound, no package global).
- [x] 1.2 Implement clone → apply stream Ip/header delta → expiry sweep → single `Store` per successful tick.
- [x] 1.3 Stop TTL heap Set/Get for stream/alone memory Ip and header request keys; keep lease and `range-index` on `cache.Client`.

## 2. Stream apply wiring

- [x] 2.1 Route `storeStreamDecision` for non-Range stream/alone memory into the tick clone (deleted-before-new preserved).
- [x] 2.2 Publish live map once at end of tick; leave `hydrateRangeMembership` cadence unchanged.

## 3. Request lookup

- [x] 3.1 Add stream/alone memory lookup path that `Load()`s the live map and probes Ip plus present header keys once each.
- [x] 3.2 Skip Range when Ip slot is ban; keep live/none on cache `GetInt`/`GetMany`.
- [x] 3.3 Wire bouncer to pass live map / mode into lookup without duplicating merge semantics.

## 4. Range read path

- [x] 4.1 Ensure published Range membership Contains does not exclusive-lock immutable trees (wrapper or utilities bump).
- [x] 4.2 Confirm hydrate still replaces trees via existing `rangeMembership` atomic.Value.

## 5. Overflow and intern

- [x] 5.1 Encode intern overflow in `liveSlot` (optional leftover field) without a second Ip map.
- [x] 5.2 Keep `OriginName` and drop metrics behavior aligned with packed and overflow slots.

## 6. Tests and benchmarks

- [x] 6.1 Unit tests: tick publish, expiry on publish, delete-before-new, skip-Range-on-Ip-ban, live path unchanged.
- [x] 6.2 Benchmarks vs `origin/main`: heap retained, allocs/op, sequential/parallel miss ns/op; document fixture size on delivery card.

## 7. Verify

- [x] 7.1 Run `go test` for `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`, and related packages.
