# Scope

1. [judgement] Scope vs Requirements — `requirement.md` — Desired (decisions 1, 4; Ticket 2026-11-21-lapi-ban-retry-after) says no `Retry-After` on Range-scope bans; the diff drops it only for stream/alone Range winners and sends it for Range decisions LAPI returns in live/none (README `BouncerRemediationStatusCode`, `knowledge/devdocs/core_plugin_middleware_ban-page.md`)
   Quote:
   ```
      - No `Retry-After` when the written status is not 429, on AppSec bans (any status), on failure-action / technical bans (LAPI unreachable, cache/Redis failure, unhealthy stream), and on Range-scope bans (decisions 1, 4).
   ```
   Note:
   ```
      Present: stream/alone Range winner returns time left 0 (`pkg/decisionstore/lookup.go` lookupHits), README states that Range exception. Unclear: decision 4 gives the Range-index blob (stream/alone only) as its reason, and live/none `?ip=` returns the Range decision with its duration, so the header goes out there. Recorded as a taken deviation in `deviations.md`; needs the human to confirm the narrower reading of decision 4.
   ```
   Fix: Confirm with the human that decision 4 covers stream/alone only; otherwise drop the end for Range-scope decisions in the live/none path and update the README sentence
   Status: skipped
   Argument: judgement; the narrower reading of decision 4 is the taken deviation in `deviations.md` (Requester: not asked), which goes to the requester on the card.
