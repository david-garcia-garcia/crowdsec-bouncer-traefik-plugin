Developer review: in progress — 2026-09-05T16:27:36Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On master, `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins, so Country/AS ingest for the second route is wrong. Until this PR lands, operators cannot attach two header maps to one LAPI in the same Traefik.

## Merge readiness
Explore recorded identity ownership; product code has not changed yet. 1 item remains.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: a4e2857
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore done; CI in progress; no product apply |
| CI proof | 3/6 | Checks in progress (Main Process succeeded on prior head) |
| Local tests proof | N/A | Before implement; remote CI covers proof |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-scope-headers-identity pushed | `git` origin/2026-09-05-scope-headers-identity |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/18 | GitHub MCP |
| CI | build 33977880780 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33977880780 | GitHub MCP get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub MCP |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |
| Dead | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-05-scope-headers-identity, stub PR 18. Explore decided the normalized map belongs on `crowdsecconnection` identity; Bouncer reads a getter. Qualify remains qualified-with-gaps.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should identity hash the raw Traefik map or `NormalizeDecisionScopeHeaders` output? | assumed — hash the normalized map so `Country` vs `country` do not split connections. | explore |
| Empty map vs omitted map — same connection? | assumed — yes. `NormalizeDecisionScopeHeaders` returns nil for both; stream stays `ip,range`. | explore |
| Hash full scope→header map, or only sorted scope keys (keep header names on Bouncer)? | assumed — full map on identity; Bouncer has no copy. Different header names are different connections. | explore |
| Two local connections with the same LAPI key will still share CrowdSec `stream_cursor`. Block this ticket? | assumed — no. Ticket is local stream/cache isolation. Do not mint a second API key here. | explore |
| Getter name on CrowdsecConnection? | assumed — `DecisionScopeHeaders()` returning the stored normalized map. Callers must not mutate it. | explore |

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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | a4e2857992f3ab9b2e17891101bfebfb28d8e573 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus master. Explore chose identity ownership of the normalized map.

Do we have a high-confidence way to reproduce? Yes, `identity.go` omits the map so `Key` collides for two maps on one LAPI.

Is this the best way to solve the issue? Yes versus master: stream `scopes=` is a connection fact, unlike per-route AppSec failure action.

### Evidence
What I checked:
- `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md` identity field list omits decisionScopeHeaders
- `knowledge/devdocs/core_plugin_decisionscope.md` currently avoids putting Country on the reclaim key
- LAPI cursor is per bouncer row (`knowledge/research/ext_crowdsec_lapi_stream-cursor/`)

### Rank-up moves
None.
