Developer review: in progress — 2026-09-06T16:58:52Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `master`, the AppSec `Query` path in `pkg/appsec` leaks HTTP connections on 502/503/504, can forward POST bodies with stale length/hop-by-hop headers after truncation, bans clients on response read errors even when `crowdsecAppsecFailureAction` is passthrough or captcha, and silently drops POST bodies when `crowdsecAppsecBodyLimit` is `0`. Under sustained AppSec gateway errors or misconfiguration, operators see pool exhaustion, weakened WAF coverage, and fail-closed behavior contrary to configured failure action.

## Merge readiness
Prepare complete; product fix not started. 7 workflow items remain.

Priority: P2 — real operator pain with workaround or limited blast radius
Reviewed head: e91d6dc
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | No product delta yet |
| CI proof | 1 | Pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-appsec-query-hardening pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/35 | GitHub |
| CI | not seen | pr-host |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt spec `2026-09-06-appsec-query-hardening` → branch `2026-09-06-appsec-query-hardening` → stub PR #35 → explore next for body-limit `0` contract.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should `crowdsecAppsecBodyLimit: 0` mean unlimited, be rejected at validate, or trigger failure-action when a body would be dropped? | assumed — explore will pick one documented contract; do not silently drop | prepare |

## Before merge
- [ ] [P2] Fix AppSec response drain on 502/503/504 (`pkg/appsec/query.go`)
- [ ] [P2] Rebuild outbound Content-Length and hop-by-hop headers after body truncation
- [ ] [P2] Apply `failureAction` on response read errors
- [ ] [P2] Define and implement body-limit `0` contract with test
- [x] Prepare: dump, requirement, stub PR

Do not list the eight workflow phases here. Those live on `devstate/progress.md`.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No OpenSpec change yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | e91d6dc | Bus-only prepare commit |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — no product diff yet.

Do we have a high-confidence way to reproduce? Yes — sibling findings cite `pkg/appsec/query.go` paths and missing tests.

Is this the best way to solve the issue? Not yet assessed — explore and propose pending.

### Evidence
What I checked:
- Local bug-hunt specs under `devstate/bug-hunt/2026-09-06/appsec/` (caller repo)
- `pkg/appsec/query.go`, `client.go`, `bouncer.go`, `configuration.go` on `origin/master` (8186c16)

### Rank-up moves
None.
