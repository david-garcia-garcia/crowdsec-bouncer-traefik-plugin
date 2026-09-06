Developer review: in progress — 2026-09-06T15:07:12+00:00

IssueKey: 2026-09-06-upstream-339-captcha-custom-resource-passthrough
JobName: 2026-09-06-upstream-339-captcha-custom-resource-passthrough

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `master`, captcha-flagged IPs using `captchaProvider=custom` cannot fetch custom JS and challenge assets on the same bouncer-protected route; `handleRemediationServeHTTP` serves captcha HTML instead of passing through to origin. Deployments like wicketkeeper (`/fast.js`, `/v0/challenge`) stay broken until asset URLs bypass captcha remediation while bans remain blocked.

## Merge readiness
Prepare complete; explore is next. Product delta versus `master` is journal only.

Priority: P2 — real end-user pain (custom captcha cannot load) with limited blast radius
Reviewed head: 016014c
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | Before implement; journal-only branch |
| CI proof | 1/6 | Branch pushed; CI not seen |
| Local tests proof | N/A | before implement; remote CI covers proof |
| Review resolution | 6/6 | OPEN PR #50, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-339-captcha-custom-resource-passthrough pushed | git origin |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/50 | GitHub |
| CI | not seen | not measured this Set |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local upstream#339 assessment on `2026-09-06-upstream-339-captcha-custom-resource-passthrough` from `origin/master`, stub PR #50, requirement grounded in bouncer/captcha/config paths.

## Decision needed
None.

## Before merge
- [ ] Run explore phase (URL match semantics, challenge URL requiredness, HEAD behavior)
- [x] Stub PR #50 open from `2026-09-06-upstream-339-captcha-custom-resource-passthrough`
- [x] requirement.md written (qualified-with-gaps)

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No OpenSpec change yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |
| Reviewed head | 016014c | Journal-only prepare commit |

### Stored data model
None.

### Technical review
Best possible solution: not merged yet. Ticket asks for `CaptchaCustomChallengeURL` plus pass-through on captcha-flagged requests matching JS/challenge URLs; ban path must stay blocked.

Do we have a high-confidence way to reproduce? Not yet — no unit test on master for custom asset pass-through; explore should define match rules.

Is this the best way to solve the issue? Pending explore on URL equality vs path-only matching and optional vs required challenge URL.

### Evidence
What I checked:
- `pkg/bouncer/bouncer.go` handleRemediationServeHTTP captcha branch
- `pkg/configuration/configuration.go` custom captcha fields
- `pkg/captcha/captcha.go` template embed of CaptchaCustomJsURL
- `examples/custom-captcha/README.md` wicketkeeper paths
- upstream#339 local dump + assessment (recommended-action: fix)

### Rank-up moves
None.
