# traefik-middleware-utilities backendbackoff gate

## Module pin

- Module: `github.com/david-garcia-garcia/traefik-middleware-utilities` (Go 1.21).
- Package lives at repo root as `backendbackoff/`, not under `pkg/`.
- Latest tag: `v1.0.3` = `950b08de86b6fd9ea68ac1d205e17a379ec60522`. Default-branch HEAD on 2026-09-18 is that same commit. The tag **includes** `backendbackoff` (Allow/Report/Close, Yaegi tests).
- Dest `go.mod` already requires `v1.0.3`. Dest `vendor/modules.txt` lists only `reclaim` and `simpleredis` because dest does not import `backendbackoff` yet. `go mod vendor` after an import will add the package without a version bump.

## API (v1.0.3)

- `New(Config) (*Gate, error)`. Fully zero `Config` applies packaged defaults. Partial `Config`: a zero field gets its default, except `Jitter` 0 stays 0 and disables jitter (not skip).
- Defaults: `FailureRatio` 0.30, `TripFailures` 5, `BaseCooldown` 1s, `MaxCooldown` 10s, `Jitter` 0.10, `TTL` 60s.
- Construction fails when `FailureRatio` is not in (0, 1), `TripFailures` < 1, `BaseCooldown` ≤ 0, `MaxCooldown` < `BaseCooldown`, `Jitter` not in [0, 1), or `TTL` < 1s. A zero `FailureRatio` or `TripFailures` is filled to the default, then validated — there is no published “never trip / disable skip” knob.
- `Allow(ctx, key) (ok bool, wait time.Duration, err error)`. Done `ctx` returns that error and does not admit. Closed gate returns `backendbackoff: gate is closed` and does not admit. Denied (OPEN cooldown or outstanding HALF-OPEN probe) returns `ok=false`, remaining wait, `err=nil`. The library does not sleep and does not write HTTP. Caller owns `key`.
- `Report(key, success bool) error` — outcome of an attempt the gate admitted. No `context`. Denied Allows must not be Reported; if they are, OPEN with no outstanding probe is ignored. After `B` consecutive CLOSED failures the key is OPEN; a successful HALF-OPEN probe restores CLOSED with full credit.
- `Close()` drops the map (no error return). Later Allow/Report error and do not admit. Safe to call more than once. No Sleep/Wake.
- `SetNowForTest` is test-only.

## Disable skip

The published gate has no disable/skip-off field. Zero `Config` turns the gate **on** (defaults). Product-side skip-off is “do not construct / do not call Allow”, not a second Tracker type.

Sources: `.sources/gate.go.md`, `.sources/allow.go.md`, `.sources/std_go_backendbackoff_allow-spec.md`.
