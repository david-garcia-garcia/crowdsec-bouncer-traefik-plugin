# Skip Redis for a while after rate-limit counter failures

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

During a Redis outage every request that needs Redis spends up to the 250ms step budget before `rateLimitFailureAction` applies. A blackholed Redis host (no refusal, no answer) turns that into a fixed added latency on most requests for the whole outage.

## Why it was not taken

`simpleredis` at v1.0.7 retries with backoff inside one command but has no circuit breaker. A gate that stops calling Redis after repeated failures and probes again later is new state on the leg with its own thresholds; the explore decision kept it out of the first slice. The utilities module ships a `backendbackoff` package, which has not been evaluated for this use.

## Risks

Added latency per request during a long Redis outage, bounded at 250ms.

## Context

Owner when taken: `pkg/ratelimit` `Client` (gate before `Take`). Candidate building block: `traefik-middleware-utilities/backendbackoff` (signature changes between v1.0.7 and v1.0.8).
