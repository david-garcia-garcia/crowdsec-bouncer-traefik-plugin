Developer review: in progress — 2026-09-20T05:39:02Z

## What this changes
**Operators.** In this Traefik instance, one LAPI key is one stream ticker and one usage-metrics window. Redis and interval disagreements are ignored, not isolated. Isolation still needs a second bouncer API key. WARN names ignored fields and who joined whom.

**Admin users.** None.

**Developers.** Stream `SessionKey` is `lapi:stream:` + `SessionHex` (no Redis hash). Join reuses Client+store; DecisionStore is created inside Client create() and closed on Client Close. Live/none `Key` still includes Redis.

**End users.** None.

## Motivation
Two middlewares in one Traefik can share a LAPI host and API key while pointing at different Redis. CrowdSec still keeps one `/v1/decisions/stream` cursor and one usage-metrics window on the bouncer row selected by hashed `X-Api-Key` plus this process’s outbound IP. DestBranch hashed Redis into the stream Client Open key, so that disagreement started a second ticker. That ticker stole `startup=false` deltas and POSTed a second metrics window. Operators already have a workaround (a second bouncer key); without this change the Redis split stays silent isolation that contradicts LAPI physics.

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
Apply landed; local tests passed; remote CI still in progress. 4 items remain.

Priority: P2 — real operator pain (stolen stream deltas / second metrics window) with a workaround (second API key)
Reviewed head: 8d4d1459
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress |
| CI proof | 3/6 | Checks in progress |
| Local tests proof | N/A | Remote PR uses CI; localTests passed |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-20-lapi-session-subscribe pushed | origin/2026-09-20-lapi-session-subscribe |
| OpenSpec | 2026-09-20-lapi-session-subscribe | openspec/changes/2026-09-20-lapi-session-subscribe/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/119 | pr-host |
| CI | build 35492198105 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35492198105 | GitHub check runs |
| Local tests | passed | `go test ./pkg/lapi ./pkg/decisionstore ./pkg/bouncer .` |
| PR comments | no comments | inventory empty |

## Specs
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/openspec/changes/2026-09-20-lapi-session-subscribe/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-20-lapi-session-subscribe, dest `master`, PR 119. Apply on HEAD 8d4d1459. Next is six-axis code review.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Whether stream+live on the same key should share one metrics reporter. | assumed — no. Mode is in SessionHex; prefixes differ; do not build a cross-mode reporter. | explore |
| Whether live/none Client Key also drops Redis the same way. | assumed — no, not in this ticket. Live `?ip=` does not steal stream_cursor. | explore |

## Before merge
- [ ] Remote CI succeeded on PR 119
- [ ] Archive OpenSpec change and drop WIP from the PR title

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
| Reviewed head | 8d4d1459a77938a2b4dd87e7bb6a4af65b7da2dd | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Stream Open key matches the CrowdSec row; subscribe WARNs; store is a child of create so dropping Redis from the Client key cannot leak a zombie store.

Do we have a high-confidence way to reproduce? Yes, inverted OpenStream tests now require share+WARN; local `go test` passed.

Is this the best way to solve the issue? Yes vs DestBranch: match LAPI physics; do not fail New; live Key unchanged.

### Evidence
What I checked:
- `SessionKey` is `lapi:stream:` + `SessionHex` (`pkg/lapi/session.go`)
- README Note: Redis/interval disagreements ignored (8d4d1459)
- localTests passed; CI in progress on PR 119

### Rank-up moves
None.
