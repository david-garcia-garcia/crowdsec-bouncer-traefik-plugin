Developer review: in progress — 2026-09-06T14:58:50Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On master, `pkg/bouncer` in appsec mode never initializes the captcha client, so a valid `crowdsecAppsecFailureAction: captcha` config bans instead of serving captcha when AppSec fails. `Bouncer.New` also discards IP-checker and ban-template errors, and critical `ServeHTTP` remediation branches lack direct unit tests. If this does not land, operators can mis-remediate AppSec failures and regressions in stream-health, cache, and captcha paths will not fail CI at the bouncer layer.

## Merge readiness
Not ready for review. Prepare complete; explore next. Product delta versus `master` is journal only.

Priority: P2 — real operator mis-remediation with a workaround (ban instead of captcha), plus untested failure paths
Reviewed head: aa16b9b
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | CI not seen; no product apply |
| CI proof | 1/6 | pushed, not seen |
| Local tests proof | N/A | before implement; remote CI covers proof |
| Review resolution | 6/6 | OPEN PR #33, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-bouncer-init-and-servehttp pushed | `git` origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/33 | pr-host |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt spec on `2026-09-06-bouncer-init-and-servehttp` from `origin/master`, stub PR #33, requirement grounded in `pkg/bouncer` with scope bound to that package.

## Decision needed
None.

## Before merge
- [ ] Fix appsec-mode captcha init so failure-action captcha serves captcha, not ban
- [ ] Surface `NewChecker` / `GetTemplate` errors from `Bouncer.New`
- [ ] Add `ServeHTTP` / remediation branch unit tests in `pkg/bouncer`
- [x] Stub PR #33 open from `2026-09-06-bouncer-init-and-servehttp`
- [x] Requirement written and qualified-with-gaps

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | aa16b9b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not yet evaluated — prepare only.

Do we have a high-confidence way to reproduce? Yes — configure appsec mode with failure-action captcha and trigger AppSec `ErrFailureCaptcha`; observe ban instead of captcha page.

Is this the best way to solve the issue? Not yet evaluated — explore will resolve init policy unknowns.

### Evidence
What I checked:
- `pkg/bouncer/bouncer.go` appsec early return before captcha init (aa16b9b)
- `pkg/bouncer/bouncer_test.go` lacks `ServeHTTP` tests (aa16b9b)
- Local bug-hunt findings in ticket dump

### Rank-up moves
None.
