Developer review: ready for review — 2026-09-05T16:48:58Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `CrowdsecConnection` reclaim identity now includes the normalized `decisionScopeHeaders` map. `Bouncer` no longer stores a copy; `ServeHTTP` reads `conn.DecisionScopeHeaders()`. Two `New()` with the same LAPI host and different maps do not `SameConnection`. Specs folded into `core_plugin_middleware_instance-reclaim` and `core_plugin_decisions_scopes`.

**End users.** None.

## Motivation
On master, `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins, so Country/AS ingest for the second route is wrong.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: 774d0fd
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open comments |
| CI proof | 6/6 | Main Process, mock e2e, and docker pester succeeded |
| Local tests proof | N/A | Remote CI covers proof |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-scope-headers-identity pushed | `git` |
| OpenSpec | put-decision-scope-headers-on-identity (archived) | `openspec/changes/archive/2026-09-05-put-decision-scope-headers-on-identity/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/18 | GitHub MCP |
| CI | build 33978659998 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978659998 | GitHub MCP get_check_runs (Main Process) |
| Local tests | passed | handoff.yaml |
| PR comments | no comments | GitHub MCP |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |
| Dead | None. | devstate/codereview.md |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-scope-headers-identity/openspec/changes/archive/2026-09-05-put-decision-scope-headers-on-identity/proposal.md) — modified
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-scope-headers-identity/openspec/changes/archive/2026-09-05-put-decision-scope-headers-on-identity/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-05-scope-headers-identity, PR 18 against master. Title is `🐛 fix(crowdsecconnection): put decisionScopeHeaders on reclaim identity`. CI on 774d0fd succeeded (Main Process, mock e2e, docker pester).

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should identity hash the raw Traefik map or `NormalizeDecisionScopeHeaders` output? | assumed — hash the normalized map so `Country` vs `country` do not split connections. | explore |
| Empty map vs omitted map — same connection? | assumed — yes. `NormalizeDecisionScopeHeaders` returns nil for both; stream stays `ip,range`. | explore |
| Hash full scope→header map, or only sorted scope keys (keep header names on Bouncer)? | assumed — full map on identity; Bouncer has no copy. Different header names are different connections. | explore |
| Two local connections with the same LAPI key will still share CrowdSec `stream_cursor`. Block this ticket? | assumed — no. Ticket is local stream/cache isolation. Do not mint a second API key here. | explore |
| Getter name on CrowdsecConnection? | assumed — `DecisionScopeHeaders()` returning the stored normalized map. Callers must not mutate it. | explore |

## Before merge
None.

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Dead
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 774d0fd043d4e7bd2b877708eb3e22f471562198 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Put the normalized map on existing reclaim identity versus master so stream `scopes=` cannot be stolen by the first `New`.

Do we have a high-confidence way to reproduce? Yes, `TestNew_DifferentDecisionScopeHeaders_IsolatedConnection`.

Is this the best way to solve the issue? Yes versus master: stream ingest is a connection fact, unlike per-route AppSec failure action.

### Evidence
What I checked:
- Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978659998
- e2e mock + docker pester success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978659993
- Five-axis review none (`codereview.md`)

### Rank-up moves
None.
