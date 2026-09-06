Developer review: in progress — 2026-09-06T14:57:31Z

IssueKey: 2026-09-06-captcha-handler-hardening
JobName: 2026-09-06-captcha-handler-hardening

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None — explore only; product changes not started.

**End users.** None.

## Motivation
On `master`, the captcha handler can 302 after a successful verify even when the grace cache write fails (solve loop), start with a nil template when no path is configured, omit `remoteip` on siteverify, return bare HTTP 400 on provider outages, and has no unit tests for these paths. Without this change, captcha remediation stays fragile under Redis errors and provider failures.

## Merge readiness
Explore complete; propose is next. 6 items remain.

Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.
Reviewed head: e526c6e
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Explore only; no product delta yet |
| CI proof | 1/6 | Branch pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-captcha-handler-hardening pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub |
| CI | not seen | gh unavailable |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → stub PR #28 → explore complete → propose next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should `cache.Client.Set` return error (API change) or captcha use a test-only wrapper? | assumed — change `Set` to return `error`; minimal surface, redis already has the error, other callers unchanged behavior when ignored. | explore |
| HTTP status on grace cache write failure — 503 vs 200 re-render? | assumed — re-render captcha 200 with Error log; less disruptive than 503; ticket allows either with operator signal. | explore |
| Backward compat for deployments with provider set but empty template path? | assumed — breaking change accepted per ticket; validation fails at startup with clear error. | explore |

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
| Specs in this PR | none | No product diff yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |
| Reviewed head | e526c6edcb13a226acbb5e686b2e6919179780cf | Bus commit on branch |

### Stored data model
None.

### Technical review
Best possible solution: Explore locked `cache.Set` error return, 200 re-render on grace write failure, startup template validation, `remoteip` on siteverify, retryable-error UX, and unit-test plan — aligned with ticket gaps on `master`.

Do we have a high-confidence way to reproduce? No — unit tests planned but not written.

Is this the best way to solve the issue? Yes — minimal API surface with clear UX and validation paths versus `master`.

### Evidence
What I checked:
- `explore.md` decisions vs `pkg/captcha/captcha.go`, `pkg/cache/cache.go`, `pkg/configuration/configuration.go` (HEAD e526c6e)
- `requirement.md` code anchors cross-checked in explore
- Stub PR #28 open on branch `2026-09-06-captcha-handler-hardening`

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]
