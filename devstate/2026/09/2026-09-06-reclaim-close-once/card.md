Developer review: ready for review — 2026-09-06T15:08:00Z

[sgsi-dev-ticket-status:2026-09-06-reclaim-close-once]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/reclaim` grace dispose now calls `Close` exactly once via the first-Open life watcher; `fire` cancels life only. Tests assert a single Close on grace dispose.

**End users.** None.

## Motivation
On `master`, grace dispose (`drop` → grace → `fire`) invoked the slot `closeFn` from both `fire` and the `life` watcher, so `Close` could run twice and concurrently. That breaks the table's exactly-once dispose contract and is masked by tests that only assert `closes >= 1`. Non-idempotent closers could double-free or panic.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — internal table contract and test clarity; no current operator or end-user harm.
Reviewed head: bacdcfe
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; local tests passed; five-axis review clean |
| CI proof | 6/6 | Main Process, e2e (binary + mock LAPI), e2e (docker + pester) succeeded |
| Local tests proof | 6/6 | `go test ./pkg/reclaim/...` passed |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-reclaim-close-once pushed | git push |
| OpenSpec | reclaim-close-once (archived) | openspec/changes/archive/2026-09-06-reclaim-close-once/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/36 | pr-host |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041016077; e2e success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041016073 | pr-host CI |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
- [std_go_reclaim_context-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-reclaim-close-once/openspec/changes/archive/2026-09-06-reclaim-close-once/proposal.md) — modified

## Axis review
- [Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-reclaim-close-once/devstate/2026/09/2026-09-06-reclaim-close-once/codereview_standards.md) — 0/0/0
- [Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-reclaim-close-once/devstate/2026/09/2026-09-06-reclaim-close-once/codereview_spec.md) — 0/0/0
- [Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-reclaim-close-once/devstate/2026/09/2026-09-06-reclaim-close-once/codereview_security.md) — 0/0/0
- [Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-reclaim-close-once/devstate/2026/09/2026-09-06-reclaim-close-once/codereview_performance.md) — 0/0/0
- [Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-reclaim-close-once/devstate/2026/09/2026-09-06-reclaim-close-once/codereview_dead.md) — 0/0/0

## Decision needed
None.

## Follow-up issues
None.

## Before merge
None.

## Findings
None.
