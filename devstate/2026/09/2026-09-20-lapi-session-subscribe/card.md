Developer review: in progress — 2026-09-20T05:12:39Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore recorded: stream Client key drops Redis; live/none Key does not; DecisionStore opens inside Client create(). Apply not started.

**End users.** None.

## Motivation
Two middlewares in one Traefik can share a LAPI host and API key while pointing at different Redis. CrowdSec still keeps one `/v1/decisions/stream` cursor and one usage-metrics window on the bouncer row selected by hashed `X-Api-Key` plus this process’s outbound IP. DestBranch hashes Redis into the stream Client Open key, so that disagreement starts a second ticker. That ticker steals `startup=false` deltas and POSTs a second metrics window. Operators already have a workaround (a second bouncer key); without this change the Redis split stays silent isolation that contradicts LAPI physics.

```mermaid
sequenceDiagram
  participant MW1 as Middleware A Redis A
  participant MW2 as Middleware B Redis B
  participant LAPI as CrowdSec bouncer row
  MW1->>LAPI: GET stream startup=false (ticker 1)
  LAPI-->>MW1: deltas; cursor advances
  MW2->>LAPI: GET stream startup=false (ticker 2)
  LAPI-->>MW2: later deltas; MW1 misses them
```

## Merge readiness
Explore complete; proceed policy on two assumed questions. Apply not started. 6 items remain.

Priority: P2 — real operator pain (stolen stream deltas / second metrics window) with a workaround (second API key)
Reviewed head: 0760a805
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress; no apply |
| CI proof | 3/6 | Checks in progress |
| Local tests proof | N/A | Before implement; remote PR uses CI |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-20-lapi-session-subscribe pushed | origin/2026-09-20-lapi-session-subscribe |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/119 | pr-host |
| CI | build 35491073835 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35491073835 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-20-lapi-session-subscribe, dest `master`, stub PR 119. Explore decided stream share+WARN; live Redis key stays. Next is propose.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Whether stream+live on the same key should share one metrics reporter. | assumed — no. Mode is in SessionHex; prefixes differ; do not build a cross-mode reporter. | explore |
| Whether live/none Client Key also drops Redis the same way. | assumed — no, not in this ticket. Live `?ip=` does not steal stream_cursor. | explore |

## Before merge
- [ ] Apply: stream Client reclaim is LAPI session; subscribe WARNs; store is a child of Client create; README says Redis/interval disagreements are ignored.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 0760a80500ad2e0c664e8ad132b6742886446c23 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Stream Open key = SessionHex without Redis; store nested in create(); WARN on subscribe mismatch. Live Key unchanged this ticket.

Do we have a high-confidence way to reproduce? Yes, four DestBranch pkg/lapi OpenStream tests passed and still encode Redis isolation.

Is this the best way to solve the issue? Yes vs DestBranch: match LAPI row physics; do not fail New; do not migrate Redis.

### Evidence
What I checked:
- explore.md Decisions and Open questions (0760a805)
- `go test ./pkg/lapi` four OpenStream session tests PASS
- CI still in progress on PR 119

### Rank-up moves
None.
