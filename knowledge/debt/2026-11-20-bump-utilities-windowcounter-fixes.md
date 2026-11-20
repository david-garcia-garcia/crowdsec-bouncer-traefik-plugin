# Bump utilities when the open `windowcounter` fixes are tagged

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

The rate-limit leg builds on `windowcounter` at the pinned utilities `v1.0.7`, which still has two reproduced defects: buffered mode never re-reads the previous window from Redis (multi-replica over-admission at each window roll; branch repro fails on v1.0.7), and exact mode never retries an EXPIRE that failed on the first hit (a leaked Redis key with no TTL).

## Why it was not taken

Upstream blocker. The fixes are utilities PRs #63 and #60, open and in no tag; no commit touches `windowcounter/` between `v1.0.7` and `v1.0.8`. Patching `vendor/` is not allowed (CI re-vendors). Fixing the utilities repo is out of scope for this ticket. Finding: `knowledge/research/ext_traefik-middleware-utilities_windowcounter/`.

## Risks

With `rateLimitSyncRate > 0` and several Traefik replicas, a bucket can admit up to `(true previous − node's previous) × weight` extra hits early in each window. Exact mode (`rateLimitSyncRate: 0`) is not affected by that one. Utilities PR #62 also changes the buffered-outage contract (nil error instead of error + local verdict), so the bump must re-check the failure-action path.

## Context

Workaround this change ships: vendor `windowcounter` at `v1.0.7`, document the replica bound next to `rateLimitSyncRate`, and apply `rateLimitFailureAction` whenever `Take` returns an error.
