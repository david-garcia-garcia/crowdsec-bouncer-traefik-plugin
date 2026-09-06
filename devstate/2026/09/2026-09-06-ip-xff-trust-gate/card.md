Developer review: in progress — 2026-09-06T14:59:13Z

IssueKey: 2026-09-06-ip-xff-trust-gate
JobName: 2026-09-06-ip-xff-trust-gate

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None — prepare only; product changes not started.

**End users.** None.

## Motivation
On `master`, `GetRemoteIP` honors `X-Forwarded-For` (or a custom header) without verifying `req.RemoteAddr` is a trusted proxy. A direct client can forge a hop chain and be identified as another IP for ban, captcha, and cache decisions. With the default empty trusted-hop pool, any present header wins over the socket peer. Unparseable-hop fail-closed behavior is untested. Without this change, client-IP spoofing remains possible at the plugin layer.

## Merge readiness
Prepare complete; explore is next. 7 phases remain.

Priority: P1 — production is unsafe today (forged client IP drives security decisions).
Reviewed head: 5a83878
Owner decision: None.

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
| Branch | 2026-09-06-ip-xff-trust-gate pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/39 | GitHub |
| CI | not seen | MCP list only |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-ip-xff-trust-gate` → stub PR #39 → explore next.

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
| Reviewed head | 5a83878c6d073b25397e1ae4c2c10ef407bcefdb | Start commit on branch |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — prepare only.

Do we have a high-confidence way to reproduce? Yes — unit tests described in requirement (direct connection + forged header; empty trusted pool).

Is this the best way to solve the issue? Not yet evaluated — explore/propose next.

### Evidence
What I checked:
- `pkg/ip/checker.go` GetRemoteIP / getIP (8186c16 on master)
- Bug-hunt findings ip-xff-trust-gate, xff-without-remoteaddr-trust-gate, getremoteip-unparseable-hop-untested
- Stub PR #39 opened (5a83878)

### Rank-up moves
None.
