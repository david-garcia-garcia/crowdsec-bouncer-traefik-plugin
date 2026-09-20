Developer review: in progress — 2026-09-20T05:21:49Z

## What this changes
**Operators.** None yet (README apply still pending). Specs describe: one LAPI key = one stream ticker and metrics window in this process; Redis/interval disagreements are ignored, not isolated.

**Admin users.** None.

**Developers.** OpenSpec change `2026-09-20-lapi-session-subscribe` folds four leaves: reclaim-key, decisionstore store, middleware bouncer, LAPI connection. Apply not started.

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
Propose apply-ready (18 tasks). Product code not started. 5 items remain.

Priority: P2 — real operator pain (stolen stream deltas / second metrics window) with a workaround (second API key)
Reviewed head: 6a5222de
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
| OpenSpec | 2026-09-20-lapi-session-subscribe | openspec/changes/2026-09-20-lapi-session-subscribe/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/119 | pr-host |
| CI | build 35491471361 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35491471361 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-20-lapi-session-subscribe, dest `master`, stub PR 119. OpenSpec folded four existing leaves. Next is implement.

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
| Specs in this PR | 0 added / 4 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6a5222de1b54c9f30a061d7aa952c1f479326fdb | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Fold reclaim-key + store child + constructor bind + first-create INFO onto existing leaves. No new 4th part.

Do we have a high-confidence way to reproduce? Yes, DestBranch OpenStream Redis-isolation tests.

Is this the best way to solve the issue? Yes vs DestBranch: match LAPI row; do not fail New; live Key unchanged.

### Evidence
What I checked:
- FindSpecHost four folds high confidence (`devstate/.../specs.md`)
- `openspec/changes/2026-09-20-lapi-session-subscribe/` proposal + 18 tasks (6a5222de)
- CI in progress on PR 119

### Rank-up moves
None.
