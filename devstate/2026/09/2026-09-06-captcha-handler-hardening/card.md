Developer review: in progress — 2026-09-06T16:56:30Z

IssueKey: 2026-09-06-captcha-handler-hardening
JobName: 2026-09-06-captcha-handler-hardening

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None — prepare only; product changes not started.

**End users.** None.

## Motivation
On `master`, the captcha handler can 302 after a successful verify even when the grace cache write fails (solve loop), start with a nil template when no path is configured, omit `remoteip` on siteverify, return bare HTTP 400 on provider outages, and has no unit tests for these paths. Without this change, captcha remediation stays fragile under Redis errors and provider failures.

## Merge readiness
Prepare complete; explore is next. 7 items remain.

Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.
Reviewed head: 9995408
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Prepare only; no product delta yet |
| CI proof | 1/6 | Branch pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-captcha-handler-hardening pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub MCP |
| CI | not seen | not measured |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → stub PR #28 → CI pending → explore next.

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
| Specs in this PR | none | No product diff yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |
| Reviewed head | 9995408 | Bus commit on branch |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — prepare only.

Do we have a high-confidence way to reproduce? No — unit tests not yet written.

Is this the best way to solve the issue? Not yet assessed — explore/propose pending.

### Evidence
What I checked:
- Ticket grounded against `pkg/captcha/captcha.go`, `pkg/cache/cache.go`, `pkg/configuration/configuration.go`, `pkg/bouncer/bouncer.go` (HEAD 9995408)
- Stub PR #28 opened on GitHub

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]
