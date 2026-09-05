Developer review: in progress — 2026-09-05T16:30:47Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `put-decision-scope-headers-on-identity` folds `core_plugin_middleware_instance-reclaim` and `core_plugin_decisions_scopes` so the normalized `decisionScopeHeaders` map is on CrowdsecConnection identity. Go apply is not landed yet.

**End users.** None.

## Motivation
On master, `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins, so Country/AS ingest for the second route is wrong. Until this PR lands, operators cannot attach two header maps to one LAPI in the same Traefik.

## Merge readiness
Proposal is apply-ready; product Go has not changed yet. 1 item remains.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: ade8383
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Proposal landed; CI in progress; Go apply not done |
| CI proof | 3/6 | Main Process and mock e2e succeeded; docker pester in progress |
| Local tests proof | N/A | Before implement; remote CI covers proof |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-scope-headers-identity pushed | `git` |
| OpenSpec | put-decision-scope-headers-on-identity | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/18 | GitHub MCP |
| CI | build 33978014893 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978014893 | GitHub MCP get_check_runs |
| Local tests | none | handoff.yaml |
| PR comments | no comments | GitHub MCP |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |
| Dead | None. | no codereview.md |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-scope-headers-identity/openspec/changes/put-decision-scope-headers-on-identity/proposal.md) — modified
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-scope-headers-identity/openspec/changes/put-decision-scope-headers-on-identity/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-05-scope-headers-identity, stub PR 18. Propose folded two existing specs. Next is implement.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should identity hash the raw Traefik map or `NormalizeDecisionScopeHeaders` output? | assumed — hash the normalized map so `Country` vs `country` do not split connections. | explore |
| Empty map vs omitted map — same connection? | assumed — yes. `NormalizeDecisionScopeHeaders` returns nil for both; stream stays `ip,range`. | explore |
| Hash full scope→header map, or only sorted scope keys (keep header names on Bouncer)? | assumed — full map on identity; Bouncer has no copy. Different header names are different connections. | explore |
| Two local connections with the same LAPI key will still share CrowdSec `stream_cursor`. Block this ticket? | assumed — no. Ticket is local stream/cache isolation. Do not mint a second API key here. | explore |
| Getter name on CrowdsecConnection? | assumed — `DecisionScopeHeaders()` returning the stored normalized map. Callers must not mutate it. | explore |

## Before merge
- [ ] Apply identity + getter + drop Bouncer copy
- [ ] Prove two `New()` with the same LAPI host and different maps do not `SameConnection`

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
| Reviewed head | ade8383eea083b4fc3412ba441ca1c22543f0174 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Fold the map onto existing reclaim identity versus master, matching LAPI failure action and unlike per-route AppSec failure action.

Do we have a high-confidence way to reproduce? Yes, `identity.go` omits the map.

Is this the best way to solve the issue? Yes versus master: stream `scopes=` is a connection fact.

### Evidence
What I checked:
- `openspec validate put-decision-scope-headers-on-identity` valid (openspec 1.7.0)
- FindSpecHost fold `core_plugin_middleware_instance-reclaim` and `core_plugin_decisions_scopes`

### Rank-up moves
None.
