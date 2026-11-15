---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/950b08de86b6fd9ea68ac1d205e17a379ec60522/backendbackoff/gate.go
title: backendbackoff/gate.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522:backendbackoff/gate.go
---

Package comment: Yaegi-safe in-memory admission gate for an unhealthy backend.

Defaults: FailureRatio `0.30`, TripFailures `5`, BaseCooldown `1s`, MaxCooldown `10s`, Jitter `0.10`, TTL `60s`.

Config comment: fully zero Config applies packaged defaults. On a partial Config, a zero Jitter disables jitter (tests freeze cooldowns that way).

`resolveConfig`: zero FailureRatio/TripFailures/BaseCooldown/MaxCooldown/TTL filled with those defaults. Jitter default applied only when `cfg == Config{}` (`allZero`). Then validate FailureRatio in (0,1), TripFailures >= 1, BaseCooldown > 0, MaxCooldown >= BaseCooldown, Jitter in [0,1), TTL >= 1s.

States: CLOSED, OPEN, HALF-OPEN. `budget = float64(TripFailures)`. `successCredit` = `p/(1-p)`. `cooldownDuration(n)` doubles BaseCooldown n times, caps at MaxCooldown, then ±Jitter if Jitter > 0.

`Close` sets `closed` and nils `keys`; later Allow/Report return `errClosed`.
