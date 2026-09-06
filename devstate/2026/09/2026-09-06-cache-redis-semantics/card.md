Developer review: ready for review — 2026-09-06T15:28:00Z

[sgsi-dev-ticket-status:2026-09-06-cache-redis-semantics]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `Client.Set`/`Delete` return errors; `duration <= 0` is a documented no-op on memory and Redis; Redis reads route to the writer for keys this instance wrote; Redis CRUD parity tests added; mock e2e redis scenario updated for read-your-writes.

**End users.** None.

## Motivation
On master, Redis and memory cache diverge on TTL-zero writes, swallow Set/Delete failures, and read only from round-robin replicas — so bans, stream leases, and captcha grace can miss immediately after a write that appeared to succeed. CI exercised CRUD only on `localCache`, leaving Redis regressions invisible.

## Merge readiness
All checks green; ready for review. 1 follow-up noted.

Priority: P2 — real operator pain when Redis replica lag or write failures hide remediations, with limited blast radius until upstream callers fail closed.
Reviewed head: b93e2d0
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded, local tests passed |
| CI proof | 6/6 | Main Process + both e2e jobs succeeded |
| Local tests proof | 6/6 | `go test ./pkg/cache/ ./pkg/lapi/ ./pkg/decisionscope/` passed |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-cache-redis-semantics pushed | git push |
| OpenSpec | cache-redis-semantics | archived |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/38 | pr #38 |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041815865 ; e2e binary success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041815869 ; e2e docker success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041815869 | all green |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
- [core_cache_redis_in-tree-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-cache-redis-semantics/openspec/changes/archive/2026-09-06-cache-redis-semantics/proposal.md) — modified

## Axis review
| Axis | Result |
| --- | --- |
| [Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-cache-redis-semantics/devstate/2026/09/2026-09-06-cache-redis-semantics/codereview_standards.md) | 1/1 completed |
| [Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-cache-redis-semantics/devstate/2026/09/2026-09-06-cache-redis-semantics/codereview_spec.md) | 1/1 completed |
| [Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-cache-redis-semantics/devstate/2026/09/2026-09-06-cache-redis-semantics/codereview_security.md) | 1/1 completed |
| [Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-cache-redis-semantics/devstate/2026/09/2026-09-06-cache-redis-semantics/codereview_performance.md) | 1/1 completed |
| [Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-cache-redis-semantics/devstate/2026/09/2026-09-06-cache-redis-semantics/codereview_dead.md) | 1/1 completed |

## Decision needed
None.

## Follow-up issues
- note large — fail-closed on cache Set/Delete in pkg/lapi stream lease and pkg/captcha grace (API landed; upstream wiring deferred)

### Stored data model
None.

## Before merge
None.

## Findings
None blocking.

## Qualify
qualified-with-gaps (explore decisions resolved; upstream fail-closed deferred)
