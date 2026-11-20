---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/950b08de86b6fd9ea68ac1d205e17a379ec60522/backendbackoff/allow.go
title: backendbackoff/allow.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522:backendbackoff/allow.go
---

`Allow(ctx, key)`: if `ctx.Err() != nil` return `false, 0, err` (no lock mutation of credit). Closed gate → `errClosed`.

CLOSED: `resetNIfClosedLongEnough` then `true`. OPEN before `openUntil`: `false` plus remaining wait. OPEN after: HALF-OPEN, `probeOutstanding=true`, `probeUntil = now+BaseCooldown`, `true`. HALF-OPEN with outstanding probe before `probeUntil`: `false` plus remaining; else admit another probe.

`Report(key, success)`: missing key → nil. OPEN → nil (no-op). HALF-OPEN without outstanding probe → nil. HALF-OPEN success: credit=budget, CLOSED. HALF-OPEN failure: `n++`, OPEN for `cooldownDuration(n)`. CLOSED success: add successCredit capped at budget. CLOSED failure: decrement credit; `<= 0` → OPEN.

Comment on Report: Denied Allow is not this function’s job; expire is Allow’s job. `resetNIfClosedLongEnough`: `n = 0` after one MaxCooldown of continuous CLOSED.
