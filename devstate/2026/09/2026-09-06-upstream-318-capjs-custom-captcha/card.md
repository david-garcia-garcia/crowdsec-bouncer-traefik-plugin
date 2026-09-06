Developer review: in progress — 2026-09-06T15:06:49Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `master`, custom captcha verification always sends urlencoded `secret` and `response` via `PostForm`. CapJS Standalone expects JSON `POST` to `/siteverify` with the same keys. Operators pointing `CaptchaCustomValidateURL` at CapJS cannot verify solved challenges without an external adapter proxy, while Wicketkeeper works. Without this change, CapJS users stay blocked on custom captcha despite existing custom-provider config knobs.

## Merge readiness
Prepare complete; explore not started. 7 items remain.

Priority: P2 — real operator pain configuring CapJS custom captcha, with Wicketkeeper as workaround for urlencoded providers only.
Reviewed head: ab370f1
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | No product delta yet |
| CI proof | N/A | Before first product push |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-318-capjs-custom-captcha pushed | git / pr-host |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/52 | pr-host Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket upstream#318 → branch `2026-09-06-upstream-318-capjs-custom-captcha` → stub PR #52 opened from `master`. Requirement grounded in captcha verify path; explore next for config-surface decision.

## Decision needed
None.

## Before merge
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No OpenSpec change yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | ab370f1 | Card matches branch measured at prepare close |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — prepare only grounded the gap between urlencoded verify and CapJS JSON siteverify.

Do we have a high-confidence way to reproduce? No — no tests for custom verify behavior yet (`pkg/captcha/*_test.go` not found).

Is this the best way to solve the issue? Not yet assessed — config surface (enum vs auto-detect) deferred to explore.

### Evidence
What I checked:
- `pkg/captcha/captcha.go` Validate uses PostForm only (8186c16)
- `pkg/configuration/configuration.go` custom captcha fields (8186c16)
- CapJS Standalone docs: JSON POST siteverify (trycap.dev/guide/standalone/)

### Rank-up moves
None.
