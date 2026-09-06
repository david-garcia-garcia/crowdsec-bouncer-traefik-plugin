Developer review: ready for review — 2026-09-06T15:15:00Z

IssueKey: 2026-09-06-ip-xff-trust-gate
JobName: 2026-09-06-ip-xff-trust-gate

## What this changes
**Operators.** When using forwarded headers for client IP, list proxy addresses in `forwardedHeadersTrustedIps`; otherwise the plugin uses the socket peer only.

**Admin users.** None.

**Developers.** `GetRemoteIP` in `pkg/ip/checker.go` gates the XFF walk on a trusted `RemoteAddr`; empty trusted-hop pool ignores headers. Table-driven tests cover spoofing, empty pool, and malformed hops. Spec `core_plugin_ip_radix-lookup` and `knowledge/devdocs/core_plugin_ip.md` updated.

**End users.** None.

## Motivation
On `master`, `GetRemoteIP` honors `X-Forwarded-For` without verifying `req.RemoteAddr` is a trusted proxy. A direct client can forge a hop chain and be identified as another IP for ban, captcha, and cache decisions. With the default empty trusted-hop pool, any present header wins over the socket peer. Without this change, client-IP spoofing remains possible at the plugin layer.

## Merge readiness
All eight workflow phases complete; CI green on reviewed head.

Priority: P1 — production is unsafe today (forged client IP drives security decisions).
Reviewed head: 47eebdb
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready for review |
| CI proof | 6/6 | All 3 checks succeeded on 47eebdb |
| Local tests proof | N/A | Remote CI covers proof |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-ip-xff-trust-gate pushed | git |
| OpenSpec | ip-xff-trust-gate (archived) | openspec/changes/archive/2026-09-06-ip-xff-trust-gate/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/39 | GitHub |
| CI | Main Process success; e2e (docker + pester) success; e2e (binary + mock LAPI) success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041285139 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
- [core_plugin_ip_radix-lookup](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-ip-xff-trust-gate/openspec/changes/archive/2026-09-06-ip-xff-trust-gate/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Bug-hunt finding → branch `2026-09-06-ip-xff-trust-gate` → PR #39 → RemoteAddr gate in `GetRemoteIP` → CI green.

## Decision needed
None.

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-ip-xff-trust-gate/devstate/2026/09/2026-09-06-ip-xff-trust-gate/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-ip-xff-trust-gate/devstate/2026/09/2026-09-06-ip-xff-trust-gate/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-ip-xff-trust-gate/devstate/2026/09/2026-09-06-ip-xff-trust-gate/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-ip-xff-trust-gate/devstate/2026/09/2026-09-06-ip-xff-trust-gate/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-ip-xff-trust-gate/devstate/2026/09/2026-09-06-ip-xff-trust-gate/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 modified | core_plugin_ip_radix-lookup |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |
| Reviewed head | 47eebdbecc493cd2404137e9486b5012b3f68d99 | Matches branch HEAD |

### Stored data model
None.

### Technical review
Best possible solution: Single RemoteAddr gate in GetRemoteIP reusing the existing trusted-hop Checker; no bouncer or config changes.

Do we have a high-confidence way to reproduce? Yes — spoofing repro confirmed before fix; unit tests lock behavior.

Is this the best way to solve the issue? Yes — minimal surface, matches devdocs intent.

### Evidence
What I checked:
- `go test ./pkg/ip/ ./pkg/bouncer/` passed locally (47eebdb)
- CI Main Process + both e2e jobs succeeded (GitHub Actions run 34041285139 / 34041285102)

### Rank-up moves
None.
