# Explore
IssueKey: 2026-09-20-elapsedsec-liveslot

## Concepts

Memory `LiveSlot` is `{Word uint32, ExpiresAt int64}`. Alignment makes that 16 bytes. `ExpiresAt` is wall Unix (`time.Now().Unix() + durationSec`). Sweep and lookup use `ExpiresAt > 0 && ExpiresAt <= now`. `PublishTick(0)` is the skip-sweep sentinel. Stream apply passes `time.Now().Unix()`. Redis never stores `LiveSlot`; it uses `DurationSec` as EX TTL. Captcha cookies and metrics stay wall Unix.

Elapsed seconds since a process epoch fit in int32 (~68 years). Bias 2 keeps `0` free as the skip sentinel and `1` as “already expired” so duration `0` / `-1` still miss.

```
  wall Unix now ──► Now() = unix - originUnix (origin = init unix - 2)
                         │
                         ▼
  LiveSlot.ExpiresAt int32 ──► expired iff > 0 && <= Now()
  PublishTick(0)          ──► skip sweep (0 is never Now())
```

## Decisions

- Compact `ExpiresAt` to int32 elapsed, not Unix int32 and not int16. Reproduced: `unsafe.Sizeof` dest `LiveSlot` is 16; `{uint32,int32}` is 8.
- No `pkg/elapsedsec`. Origin and `Now` / `Expiry` stay unexported in `pkg/decisionstore` next to `LiveSlot` (one consumer).
- Origin is a package-level write-once `int64` at `init()`, not Traefik `New`, not reclaim, not `sync.Once`. Spec forbids a process-wide **map**; intern forbids a package `var` for origin **names**. This clock is neither.
- `PublishTick(now int32)` (and engine callback). Callers pass `elapsedNow()`, never `time.Now().Unix()`. Redis ignores the argument.
- `Expiry(durationSec)` saturates into `(1, MaxInt32]`. Predicate stays `ExpiresAt > 0 && ExpiresAt <= now`.
- Spec fold: `core_plugin_decisionstore_store` (memory slot encoding + PublishTick clock). Stream-apply usage snippet is a later devdocs-impact write.

## Open questions

- Q: Does a second package need the Unix-shaped elapsed clock (`pkg/elapsedsec`)?
  Decision: resolved — no. Only memory `LiveSlot` / `PublishTick` / lookup / live COW. Redis TTL, captcha cookies, metrics, EXAT stay wall Unix.
  By: explore

- Q: How is `PublishTick(now)` typed so callers cannot mix wall Unix with elapsed slots?
  Decision: resolved — change `Store.PublishTick` and the engine from `int64` to `int32`; stream apply and tests call elapsed `now()` (or `PublishTick(0)`). No named `Elapsed` type unless implement hits a remaining mix-up.
  By: propose

- Q: Who owns the origin seed (package `init`, Store, or reclaim)?
  Decision: resolved — package `init` write-once `originUnix` in `pkg/decisionstore`. Not reclaim (clock is process wall time, not a store incarnation). Not `New` (per router). Intern table stays per-Store.
  By: explore

- Q: Does this work reconstruct client address / identity?
  Decision: resolved — none. Lookup still takes the address the caller already chose (`pkg/ip.GetRemoteIP` at the bouncer).
  By: explore
