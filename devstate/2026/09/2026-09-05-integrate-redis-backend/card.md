Developer review: in progress — 2026-09-05T06:50:45.7364578Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Ticket bus and stub PR only; no plugin, cache, or e2e product code versus `master` yet.

**End users.** None.

## Motivation
On `master` the Redis cache still depends on published `simpleredis` v1.0.12 (one TCP dial per command, inline protocol). There is no real-stack e2e against a functional Redis-protocol backend. Without this PR the plugin cannot take PR #8’s pool/`MGet` client in-tree, and Dragonfly cache behaviour stays untested.

## Merge readiness
Prepare grounded the ticket; implement has not started. 7 phases remain.

Priority: P3 — tests and in-tree client packaging; no current public-contract break claimed
Reviewed head: af6fb4a
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR is up; CI not measured yet |
| CI proof | 1/6 | Pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-integrate-redis-backend pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/5 | pr-host Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | none |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-05-integrate-redis-backend` from `origin/master` (`4b8d7b2`); stub PR #5 is the durable card. Qualify is `qualified-with-gaps` (in-tree path, Dragonfly tag, mock-RESP, whether cache must call `MGet` now).

## Decision needed
None.

## Before merge
- [ ] Land in-tree simpleredis from PR #8 and Dragonfly real-stack e2e
- [ ] Green CI on PR #5

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | af6fb4aff4cb0f9dd4cb1e79a8a3ffd8cd135509 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus `master`.

Do we have a high-confidence way to reproduce? Yes, `master` vendors v1.0.12 and real-stack compose has no Redis-protocol service.

Is this the best way to solve the issue? Not applied yet.

### Evidence
What I checked:
- `go.mod` requires `github.com/maxlerebourg/simpleredis v1.0.12` (worktree at 4b8d7b2)
- `pkg/cache/cache.go` copies `SimpleRedis` by value into `readers`
- `tests/e2e/mock/mocklapi/main.go` `serveRedis` parses inline GET
- `tests/e2e/real/docker-compose.test.yml` has no Dragonfly/Redis service
- Stub PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/5 (af6fb4a)

### Rank-up moves
None.
