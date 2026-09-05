Developer review: in progress — 2026-09-05T16:40:40Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `CrowdsecConnection` reclaim identity now includes the normalized `decisionScopeHeaders` map. `Bouncer` no longer stores a copy; `ServeHTTP` reads `conn.DecisionScopeHeaders()`. Two `New()` with the same LAPI host and different maps do not `SameConnection`. Specs folded into `core_plugin_middleware_instance-reclaim` and `core_plugin_decisions_scopes`.

**End users.** None.

## Motivation
On master, `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins, so Country/AS ingest for the second route is wrong.

## Merge readiness
Change is archived and catalog synced. Remote CI is still running. 1 item remains.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: 0a42cac
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Archived; CI in progress |
| CI proof | 3/6 | Main Process in progress |
| Local tests proof | N/A | Remote CI covers proof |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-scope-headers-identity pushed | `git` |
| OpenSpec | put-decision-scope-headers-on-identity (archived) | `openspec/changes/archive/2026-09-05-put-decision-scope-headers-on-identity/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/18 | GitHub MCP |
| CI | build 33978602122 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978602122 | GitHub MCP get_check_runs |
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
Local ticket 2026-09-05-scope-headers-identity, PR 18. OpenSpec change archived. Next is pullrequest title + wait for CI.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should identity hash the raw Traefik map or `NormalizeDecisionScopeHeaders` output? | assumed — hash the normalized map so `Country` vs `country` do not split connections. | explore |
| Empty map vs omitted map — same connection? | assumed — yes. `NormalizeDecisionScopeHeaders` returns nil for both; stream stays `ip,range`. | explore |
| Hash full scope→header map, or only sorted scope keys (keep header names on Bouncer)? | assumed — full map on identity; Bouncer has no copy. Different header names are different connections. | explore |
| Two local connections with the same LAPI key will still share CrowdSec `stream_cursor`. Block this ticket? | assumed — no. Ticket is local stream/cache isolation. Do not mint a second API key here. | explore |
| Getter name on CrowdsecConnection? | assumed — `DecisionScopeHeaders()` returning the stored normalized map. Callers must not mutate it. | explore |

## Before merge
- [ ] Wait for CI to succeed
- [ ] Drop WIP from the PR title

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
| Reviewed head | 0a42cacebe8f361342b86d11f0262afaeec90541 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Put the normalized map on existing reclaim identity versus master.

Do we have a high-confidence way to reproduce? Yes, isolation test in `plugin_test.go`.

Is this the best way to solve the issue? Yes versus master.

### Evidence
What I checked:
- Catalog sync + `validate-spec-map` OK + `validate-artifact-names` OK
- Archive folder `openspec/changes/archive/2026-09-05-put-decision-scope-headers-on-identity/`

### Rank-up moves
None.
