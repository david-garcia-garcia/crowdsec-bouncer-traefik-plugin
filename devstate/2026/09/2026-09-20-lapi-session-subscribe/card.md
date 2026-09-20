Developer review: in progress — 2026-09-20T05:06:35Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Ticket grounded on `master`; stream Client reclaim still keys Redis on DestBranch. Apply not started.

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
Prepare complete; stub PR open; apply not started. 7 items remain.

Priority: P2 — real operator pain (stolen stream deltas / second metrics window) with a workaround (second API key)
Reviewed head: a0eaef6f
Owner decision: None.

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
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/119 | pr-host Create |
| CI | build 35490815261 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35490815261 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-20-lapi-session-subscribe on branch of the same name, dest `master`, stub PR 119. Next phase is explore.

## Decision needed
None.

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
| Reviewed head | a0eaef6f2d74ec6a908ff63c9fb166bc4fcc0499 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet — prepare only.

Do we have a high-confidence way to reproduce? Yes, DestBranch tests `TestOpenStream_DifferentRedisIsolatesClientAndStore` and `TestOpenStream_SleepingRedisHostDoesNotOverlapPollers` encode the second ticker.

Is this the best way to solve the issue? Not yet — explore next.

### Evidence
What I checked:
- Dest is `master` (`origin/HEAD` is `main` without pkg/lapi reclaim)
- qualify qualified; src 0b5ec995de88fe208adeea959d65f6f1ccfdbd63e6e0989431f088adeed57e82
- PR 119 OPEN; comment inventory empty
- CI Main Process / Race detector / e2e in progress at Set

### Rank-up moves
None.
