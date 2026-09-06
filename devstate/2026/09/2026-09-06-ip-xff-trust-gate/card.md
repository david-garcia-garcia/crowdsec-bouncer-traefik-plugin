Developer review: in progress — 2026-09-06T15:02:30Z

IssueKey: 2026-09-06-ip-xff-trust-gate
JobName: 2026-09-06-ip-xff-trust-gate

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None — explore only; product changes not started.

**End users.** None.

## Motivation
On `master`, `GetRemoteIP` honors `X-Forwarded-For` (or a custom header) without verifying `req.RemoteAddr` is a trusted proxy. A direct client can forge a hop chain and be identified as another IP for ban, captcha, and cache decisions. With the default empty trusted-hop pool, any present header wins over the socket peer. Unparseable-hop fail-closed behavior is untested. Without this change, client-IP spoofing remains possible at the plugin layer.

## Merge readiness
Explore complete; propose is next. 6 phases remain.

Priority: P1 — production is unsafe today (forged client IP drives security decisions).
Reviewed head: 51b5992
Owner decision: Required. See Decision needed.

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
| Branch | 2026-09-06-ip-xff-trust-gate pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/39 | GitHub |
| CI | not seen | gh pr checks |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt finding → branch `2026-09-06-ip-xff-trust-gate` → stub PR #39 → explore confirmed spoofing with repro.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Does the RemoteAddr trusted-proxy check reuse the same Checker as hop-skipping or need a separate pool? | assumed — reuse `PoolStrategy.Checker` (same `ForwardedHeadersTrustedIPs` list); bouncer already passes one `serverPoolStrategy`. | explore |
| Should empty trusted pool still walk headers when RemoteAddr is loopback or missing? | assumed — empty pool always ignores headers regardless of RemoteAddr; use RemoteAddr host only (fail closed on forwarded data). | explore |

## Before merge
- [ ] [P1] Gate forwarded headers on trusted RemoteAddr in `GetRemoteIP`
- [ ] [P1] Add unit tests for spoofing, empty pool, and malformed hops
- [x] Prepare and explore complete

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No product delta yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |
| Reviewed head | 51b599243930a5c7b33fa671d2b2985d8ce14291 | Matches branch HEAD |

### Stored data model
None.

### Technical review
Best possible solution: Add RemoteAddr trusted-proxy gate in `GetRemoteIP` before header walk; reuse existing Checker.

Do we have a high-confidence way to reproduce? Yes — untrusted RemoteAddr returns forged header IP today.

Is this the best way to solve the issue? Yes — single owner for client IP, minimal surface in `pkg/ip`.

### Evidence
What I checked:
- Repro script: spoof returns `203.0.113.10` with untrusted RemoteAddr (local go run, 51b5992)
- `pkg/ip/checker.go` header walk has no RemoteAddr gate (file read)

### Rank-up moves
None.
