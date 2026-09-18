---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/950b08de86b6fd9ea68ac1d205e17a379ec60522/backendbackoff/allow.go
title: backendbackoff/allow.go
fetched: 2026-09-18
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522:backendbackoff/allow.go
---

`Allow(ctx, key) (bool, time.Duration, error)`: ctx.Err() first (no admit). Closed gate → errClosed. CLOSED admits. OPEN before openUntil denies with remaining wait. OPEN after cooldown becomes HALF-OPEN, sets probeOutstanding, admits. HALF-OPEN with outstanding probe before probeUntil denies; otherwise admits a new probe lease (BaseCooldown).

`Report(key, success bool) error`: closed → errClosed. Missing key → nil. Expire refresh on Report. OPEN ignored. HALF-OPEN success → CLOSED full credit; failure → OPEN with next cooldown. CLOSED success adds successCredit capped at budget; failure decrements credit and trips to OPEN at ≤ 0.

Idle TTL is Allow’s job; an admitted Report after TTL still lands.
