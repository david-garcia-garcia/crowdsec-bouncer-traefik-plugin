Developer review: in progress — 2026-09-20T05:51:43Z

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
Six-axis review applied hard findings; local tests passed; remote CI still in progress. 3 items remain.

Priority: P2 — real operator pain (stolen stream deltas / second metrics window) with a workaround (second API key)
Reviewed head: 0a8291fe
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
| CI | build 35492739774 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35492739774 | GitHub check runs |
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
Local ticket 2026-09-20-lapi-session-subscribe, dest `master`, PR 119. Hard review findings applied at 0a8291fe. Next is usage-doc impact.

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
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/devstate/2026/09/2026-09-20-lapi-session-subscribe/codereview_standards.md) — 7 total, 0 pending, 6 completed, 1 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/devstate/2026/09/2026-09-20-lapi-session-subscribe/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/devstate/2026/09/2026-09-20-lapi-session-subscribe/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/devstate/2026/09/2026-09-20-lapi-session-subscribe/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/devstate/2026/09/2026-09-20-lapi-session-subscribe/codereview_dead.md) — 1 total, 0 pending, 1 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-20-lapi-session-subscribe/devstate/2026/09/2026-09-20-lapi-session-subscribe/codereview_coverage.md) — 4 total, 0 pending, 2 completed, 2 skipped

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 0a8291fe | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Stream Open key matches the CrowdSec row; subscribe WARNs; store is a child of create so dropping Redis from the Client key cannot leak a zombie store.

Do we have a high-confidence way to reproduce? Yes, inverted OpenStream tests plus Sleep Redis Lookup hit; local `go test` passed.

Is this the best way to solve the issue? Yes vs DestBranch: match LAPI physics; do not fail New; live Key unchanged.

### Evidence
What I checked:
- Six-axis files under the run root; hard/wrong items Status done (0a8291fe)
- `go test ./pkg/lapi ./pkg/decisionstore ./pkg/bouncer .` passed
- CI in progress on PR 119

### Rank-up moves
None.
