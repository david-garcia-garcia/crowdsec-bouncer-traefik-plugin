Developer review: in progress — 2026-09-06T15:06:00Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet — prepare grounded upstream #357 as present-fixed-unproven; bound action is add-tests for AppSec `action: captcha` parse and relay in `pkg/appsec` and `pkg/bouncer`.

**End users.** None.

## Motivation
On `master`, AppSec JSON `action: captcha` appears implemented (body parse plus envelope relay) but no test asserts it the way challenge is covered. Upstream #357 reports missing captcha support; without proof tests, regressions could restore the reported gap silently.

## Merge readiness
Prepare complete; explore is next. 7 workflow items remain.

Priority: P3 — test and internal clarity; no current operator or end-user harm if behavior is already correct.
Reviewed head: 4709586
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR only; no product tests or CI yet |
| CI proof | 1/6 | Pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-357-appsec-captcha-action pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/44 | GitHub MCP Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local upstream #357 assessment → branch `2026-09-06-upstream-357-appsec-captcha-action` → stub PR #44 → explore next for empty-body captcha envelope policy before test design.

## Decision needed
None.

## Before merge
- [ ] [P3] Explore empty `user_body_content` policy for AppSec captcha vs challenge
- [ ] [P3] Add captcha JSON parse and bouncer relay tests mirroring challenge coverage
- [ ] [P3] Propose OpenSpec change and land tests
- [x] Prepare: requirement, worktree, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No product diff yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | 4709586 | Matches pushed branch |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — no apply yet.

Do we have a high-confidence way to reproduce? Yes — mirror existing challenge JSON tests with `action: captcha` fixtures in `pkg/appsec/query_test.go` and `pkg/bouncer/bouncer_test.go`.

Is this the best way to solve the issue? Yes for scope — assessment bound is add-tests only; feature code already on master per devdocs and relay path.

### Evidence
What I checked:
- `pkg/appsec/query.go`, `pkg/bouncer/bouncer.go`, `knowledge/devdocs/core_plugin_appsec.md` (8186c16 / master)
- Local dump `devstate/bug-hunt/2026-09-06/upstream-issues/357*.md`

### Rank-up moves
None.
