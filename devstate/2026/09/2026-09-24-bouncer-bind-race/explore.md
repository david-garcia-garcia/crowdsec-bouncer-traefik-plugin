# Explore

## Concepts

Finding 1 only: in-place `Box.Value` mutation on the bouncer late-bind path.

```
SetAlias / ClearPublisher
        │
        ▼
 reclaim.Watch ──callback──► ReceiveLAPI|AppSec|Captcha
                                    │
                                    ▼
                              storeBinding(dest, notice.Value)
                                    │
                    ┌───────────────┴───────────────┐
                    │ prev is *Box                  │ else
                    ▼                               ▼
           boxed.Value = value          dest.Store(&Box{Value})
           (RACE vs ServeHTTP)          (first publish only)
                    │
 ServeHTTP ──► loaded* ──► reclaim.Unbox ──► boxed.Value read
```

| Unit | Path | Job |
|------|------|-----|
| `storeBinding` | `pkg/bouncer/bouncer.go` | Publish Watch notice into per-leg `atomic.Value` |
| `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha` | `pkg/bouncer/bouncer.go` | Watch callbacks; feed `storeBinding` |
| `Unbox` | `pkg/reclaim/default.go` | `Load` `*Box`, return `Value` (unsynchronized field read) |
| `Box` | vendor `…/reclaim/alias.go` | Yaegi-safe wrapper; comment: only type in watcher `atomic.Value` |
| Watch wiring | `plugin.go` | `reclaim.Watch(…, route.Receive*)` after `bouncer.New` |

Call sites that matter (roots: worktree `**/*.go` for `storeBinding`, `boxed.Value`, `Box{Value`):

- Production writers of `Box.Value` in place: **1** (`storeBinding` when `dest` already holds `*Box`).
- Production callers of `storeBinding`: **3** (`ReceiveLAPI`, `ReceiveAppSec`, `ReceiveCaptcha`).
- Production readers via `Unbox` on those fields: `loadedLAPI` / `loadedAppSec` / `loadedCaptcha` (ServeHTTP + receive* + helpers).
- Same anti-pattern outside production: **1** test helper `watchInto` in `pkg/reclaim/zzz_alias_test.go` (assigns `boxed.Value`).
- No other in-tree production mutation of `Box.Value` found.

Reproduce: **not reproduced** under `go test -race` / `go run -race` on this agent host (CGO required; no `gcc` on PATH). Plain concurrent stress of the copied `storeBinding`/`Unbox` pattern completed without an observed panic in ~200ms. Static evidence of the data race stands: concurrent write to a plain `any` field while another goroutine reads it; `atomic.Value` only publishes the `*Box` pointer.

Outside facts: in-tree only (live contract + vendor Box comment). No research slug.

## Decisions

- Chosen seam: change `storeBinding` so every update does `dest.Store(&reclaim.Box{Value: value})`; never assign `boxed.Value` in place. Keep stored concrete type `*reclaim.Box` (Yaegi).
- Keep `Unbox` / `Watch` / `Published` API unchanged (requirement Out of scope).
- Scope stays Finding 1: do not take Findings 2 or 3; no unrelated bouncer policy.
- Companion in the same change: fix `watchInto` in `pkg/reclaim/zzz_alias_test.go` to Store a new Box (same publish shape; stops tests teaching the race). See `deviations.md`.
- Leave `zzz_bind_test.go` helpers that `Store` a bare `*Client` alone this change (test bypass of Box; Unbox fallback still works; not the Watch/`storeBinding` race).
- Prove the race fix in implement on a host with cgo/`-race` (focused concurrent Unbox vs Store test). Agent explore host could not measure with the race detector.
- Live contract: `openspec/specs/core_plugin_middleware_bouncer/spec.md` requirement **Bouncer binds clients through atomic late bind** (Load only; nil must not panic; mode from published client). No new capability leaf required for Finding 1; propose may delta that requirement’s publish shape if the catalog text stays silent on immutable Box snapshots.
- Usage gap (consume): `knowledge/devdocs/core_plugin_middleware_instance-slots.md` and `std_go_reclaim.md` say Store `*Box` / Yaegi type-freeze but do not forbid in-place `Box.Value` mutation — add a Gotcha in the same change (devdocs produce at implement/devdocsimpact is fine; explore records it).

Rejected alternatives:

- Mutate under a mutex around `Box.Value` — still fights Yaegi/type story; requirement already names Store-new-Box.
- `atomic.Pointer[T]` — forbidden (Yaegi); live docs and Box comment.
- Change `Unbox` to copy under lock / change Watch to Store Box itself into subscriber atomics — Out of scope API reshape; bouncer already owns the Store.

## Open questions

- Q: Does every bind update Store a new immutable *reclaim.Box (no in-place Box.Value write)?
  Rank: bounded asked — enumerated 3 Receive* callers + Unbox readers under pkg/bouncer + pkg/reclaim; Desired names Store new Box each update
  Decision: resolved — yes; that is the Finding 1 fix shape.
  By: explore

- Q: Does any other in-tree watcher still mutate Box.Value in place?
  Rank: additive asked — requirement Unknowns; search of worktree Go sources for boxed.Value and storeBinding
  Decision: resolved — production only storeBinding; test helper watchInto also mutates. Include fixing watchInto in this change (Store new Box). No other sites.
  By: explore

- Q: Exact race window under Yaegi vs native Go — measure before deciding the fix?
  Rank: additive asked — requirement Unknowns
  Decision: assumed — same immutable Box publish for both runtimes; Yaegi still needs type-stable *Box Stores and Unbox still reads Value without sync. Implement measures with go test -race where cgo exists; explore host could not.
  By: explore

- Q: Change reclaim Watch / Unbox API as part of Finding 1?
  Rank: additive asked — requirement Out of scope forbids API reshape beyond Finding 1
  Decision: resolved — no; only storeBinding (and matching test helper) publish shape.
  By: explore

- Q: Who owns client identity / address / Host for this change?
  Rank: additive asked — explore rule when work would set or reconstruct identity
  Decision: resolved — none; Finding 1 does not set or reconstruct client address, user, tenant, or Host. Reuse existing ServeHTTP / pkg/ip ownership unchanged.
  By: explore

Verdict: in progress
