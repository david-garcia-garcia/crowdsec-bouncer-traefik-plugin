Developer review: in progress — 2026-09-05T16:25:01Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On master, `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins, so Country/AS ingest for the second route is wrong. Until this PR lands, operators cannot attach two header maps to one LAPI in the same Traefik.

## Merge readiness
Prepare grounded the isolation hole; product code has not changed yet. 1 item remains.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: 9c4e6cb
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR opened; CI not seen; no product apply yet |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement; remote CI covers proof |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-scope-headers-identity pushed | `git` origin/2026-09-05-scope-headers-identity |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/18 | GitHub MCP Create |
| CI | not seen | GitHub checks not queried yet |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub MCP get_comments / get_review_comments |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |
| Dead | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-05-scope-headers-identity on branch of the same name, stub PR 18 against master. Qualify is qualified-with-gaps (usage packet currently avoids putting Country on the reclaim key; LAPI stream_cursor still shared for the same API key). Human override: continue.

## Decision needed
None.

## Before merge
- [ ] Put the normalized `decisionScopeHeaders` map on reclaim identity so different maps do not share a CrowdsecConnection
- [ ] Drop the duplicate map on `Bouncer`; read the connection’s map
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
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 9c4e6cb6b6e56f1d9842c04e2fd87c7eabbfd0fc | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus master.

Do we have a high-confidence way to reproduce? Yes, two `New()` with the same LAPI host and different `decisionScopeHeaders` currently `SameConnection` (`plugin.go` reclaim key, `identity.go`).

Is this the best way to solve the issue? Not applied yet; preferred shape is identity ownership of the normalized map.

### Evidence
What I checked:
- identity omits DecisionScopeHeaders (`pkg/crowdsecconnection/identity.go`, 9c4e6cb)
- Bouncer and CrowdsecConnection both copy the map (`pkg/bouncer/bouncer.go`, `pkg/crowdsecconnection/connection.go`)
- Stub PR 18 opened (GitHub MCP create_pull_request)

### Rank-up moves
None.
