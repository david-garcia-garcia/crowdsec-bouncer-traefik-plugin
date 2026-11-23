# Security

1. [judgement] Fail-open on deny — `pkg/configuration/configuration.go:391` — the ModSec gate is now on by default and `bouncerModsecBackOffAction` defaults to `passthrough`, so a router that set `bouncerModsecFailureAction: ban` now lets requests through without CRS during each cooldown; the owner chose these defaults, but the "Changed defaults" table in `docs/failure-modes.md` did not say it
   Fix: Name the effect and the per-router key that keeps it closed under the "Changed defaults" table
   Status: done
   Argument: Owner-chosen defaults kept; added a paragraph under the "Changed defaults" table in `docs/failure-modes.md` naming the ModSec failure-ban (fails open during the cooldown) and LAPI failure-passthrough (bans during the cooldown) effects and the per-router backoff key that keeps the old answer.
