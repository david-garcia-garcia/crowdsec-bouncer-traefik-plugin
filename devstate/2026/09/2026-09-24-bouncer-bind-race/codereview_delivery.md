# Delivery

## Motivation
Per-router bouncer bindings hold LAPI, AppSec, and captcha clients in `atomic.Value` as `*reclaim.Box`. Watch publishes into those fields while `ServeHTTP` Unboxes the stored pointer and reads `Box.Value` with no sync.

After the first publish, `storeBinding` reused the same Box and assigned `boxed.Value = value`. Concurrent Unbox could see a torn `any` (panic on the request path, which has no recover) or a nil/stale client (wrong failure action or LAPI mode). Yaegi still requires the stored concrete type to stay `*reclaim.Box`.

Leaving that in-place mutation races production traffic whenever an owner republishes while requests are in flight.

Priority: P1 — production is unsafe today on concurrent bind update vs ServeHTTP

## Implementation
`storeBinding` always publishes with `dest.Store(&reclaim.Box{Value: value})` and no longer mutates an already-published Box. Receive* feeders, Unbox, and Watch stay unchanged. Focused concurrent Unbox-vs-Store and new-Box-pointer tests land in `pkg/bouncer`. Usage Gotchas on instance-slots and std_go_reclaim name the immutable-publish rule. The explore-proposed `watchInto` companion stays deliberately unbuilt.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Watcher bindings that Store into `atomic.Value` must publish a new `*reclaim.Box` on every update; never assign `Box.Value` in place on a Box already Loadable by Unbox.
**End users.** None.
