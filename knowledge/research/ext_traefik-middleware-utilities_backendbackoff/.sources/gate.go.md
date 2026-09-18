---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/950b08de86b6fd9ea68ac1d205e17a379ec60522/backendbackoff/gate.go
title: backendbackoff/gate.go
fetched: 2026-09-18
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522:backendbackoff/gate.go
---

Package comment: Yaegi-safe in-memory admission gate for an unhealthy backend.

`New(cfg Config) (*Gate, error)`. Zero Config applies defaults. `resolveConfig` fills zero FailureRatio/TripFailures/BaseCooldown/MaxCooldown/TTL; Jitter default 0.10 only when Config is fully zero. Partial Config with Jitter 0 keeps 0.

Defaults: FailureRatio 0.30, TripFailures 5, BaseCooldown 1s, MaxCooldown 10s, Jitter 0.10, TTL 60s.

Validation errors: FailureRatio not in (0,1); TripFailures < 1; BaseCooldown ≤ 0; MaxCooldown < BaseCooldown; Jitter not in [0,1); TTL < 1s.

`Close()` sets closed, nils the map. `SetNowForTest` replaces the clock.

Credit budget starts at TripFailures. Success credit is p/(1-p). Cooldown is BaseCooldown * 2^n, jittered, capped at MaxCooldown.
