Developer review: in progress — 2026-09-05T09:35:23Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research packet `knowledge/research/ext_crowdsec_decisions_scopes/` is on this branch so later phases can cite CrowdSec LAPI scopes. Product matching is still exact IP only, same as `master`.

**End users.** None.

## Motivation
On `master` the bouncer stores and looks up only the client IP. CrowdSec already issues Range, Country, AS, and other scoped decisions; those never match. A distributed DDoS is many IPs, so per-IP bans cannot keep up. Without this PR, `master` stays Ip-only while upstream [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) (closes [#271](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271); supersedes [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368)) stays aimed at upstream `main`.

## Merge readiness
Prepare is grounded; explore has not started. Product Range/header matching and real e2e are not on the branch yet. Several items remain.

Priority: P2 — operators cannot honor Range or header-mapped CrowdSec decisions on `master` today
Reviewed head: 5b70060
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Stub PR open; Main Process in progress; no product apply yet |
| CI proof | 3/6 | Main Process in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33958393121/job/101285769024 |
| Local tests proof | N/A | `localTests: none`; remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-support-range-and-header-decisions pushed | `git` at `5b70060fc3fb836aad9fadc40e86dffef8f6c8a5` |
| OpenSpec | none | no change folder |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/7 | pr-host Create |
| CI | Main Process in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33958393121/job/101285769024 | GitHub check runs on PR 7 |
| Local tests | none | handoff.yaml |
| PR comments | no comments | none |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Caller asked to repurpose upstream [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) onto this fork's `master` (not upstream `main`), mention [#271](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271) and [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368), and add real-stack e2e for the new types. Branch `2026-09-05-support-range-and-header-decisions` → [PR 7](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/7). Qualify: qualified-with-gaps (cscli Country injection and Yaegi file placement). Fork [PR 3](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/3) (`newdecisions` → `main`) is not reused.

## Decision needed
None.

## Before merge
- [ ] Explore, propose, and implement Range + `decisionScopeHeaders` on the `pkg/bouncer` layout
- [ ] Real-stack e2e for Range and a header-mapped scope
- [ ] CI succeeded on this PR

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 5b70060fc3fb836aad9fadc40e86dffef8f6c8a5 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: port PR 383 onto `master`'s split packages and use in-tree SimpleRedis `MGet`; prove Range and header scopes with `tests/e2e/real/`.

Do we have a high-confidence way to reproduce? Not yet. Prepare located exact-IP-only lookup; product apply has not started.

Is this the best way to solve the issue? Yes. Cherry-picking 383 onto `master` as-is would miss the `pkg/bouncer` split and skip real e2e the caller asked for.

### Evidence
What I checked:
- ServeHTTP looks up only `remoteIP` (`pkg/bouncer/bouncer.go`)
- Stream cache keys `decision.Value` and never reads `Decision.Scope` (`pkg/crowdsecconnection/connection.go`)
- Real e2e `Add-TestDecision` is `--ip` only (`tests/e2e/real/TestUtils.ps1`)
- Upstream PR 383, issue 271, PR 368 (GitHub MCP)
- Research copied from `origin/newdecisions` into `knowledge/research/ext_crowdsec_decisions_scopes/`

### Rank-up moves
None.
