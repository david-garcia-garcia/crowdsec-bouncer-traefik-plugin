# Extract a common leg abstraction from `plugin.go` and `Bouncer`

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

Each published leg (LAPI, AppSec, captcha) is wired by hand in the same five places: a `leg*` constant and a `switch` arm in `openOwnedLeg` and `claimOwnedLeg` (`plugin.go`), a rollback branch in `claimOwned`, one `reclaim.Watch` call in `New`, and four per-leg fields on `Bouncer` (`*Bound`, `*Received`, `*ReceiveSeen`, `subscribe*`) plus a `Receive*` / `receive*` / `loaded*` trio in `pkg/bouncer/bouncer_leg_*.go`. The owner asked to suggest a shared leg unit before another leg is added.

## Why it was not taken

The rate-limit leg in `2026-11-20-add-redis-rate-limit-leg` is Open-only: it is not published under an instance name (requirement Out of scope), so it needs none of the alias / Watch / Receive copies. Extracting the abstraction rewrites the three existing legs and their tests; it is a refactor of shipped wiring with no rate-limit criterion behind it.

## Risks

The next published leg (or publishing the rate limiter as a shared instance) copies the five places a fourth time, and the rollback order in `claimOwned` grows by hand.

## Context

Current: `plugin.go` (`openOwnedLeg`, `claimOwnedLeg`, `claimOwned`, `New`), `pkg/bouncer/bouncer.go` (`Bouncer` fields), `pkg/bouncer/bouncer_leg_lapi.go`, `bouncer_leg_appsec.go`, `bouncer_leg_captcha.go`.
Proposed: one leg descriptor (group name, Open, ownership key, Watch empty value, receive hook) iterated by `openOwned` / `claimOwned` / `New`, and one generic binding type on `Bouncer`. Related vocabulary debt: `knowledge/debt/2026-09-23-leg-instance-backend-vocabulary.md`.
