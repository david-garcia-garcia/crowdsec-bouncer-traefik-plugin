Developer review: in progress — 2026-09-05T12:16:47Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `prove-redis-readers-by-pointer` folds a `Client.New` pointer-storage scenario into `core_cache_redis_in-tree-client`. The unit test is not landed yet.

**End users.** None.

## Motivation
On `master`, pooled `SimpleRedis` readers are pointers, but `Test_nextReader` never calls `Client.New`. Without a construction-site test, the copy-by-value pattern from [upstream #381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) can return (go vet `copylocks` on the pool mutex) and this fork would not notice.

## Merge readiness
Propose is apply-ready. Measured CI succeeded. The proving test is not committed yet. 1 product item remains.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: a05d6c1
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Measured CI succeeded; no open comments |
| CI proof | 6/6 | Main Process succeeded |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-verity-redis-reader pushed | `git` / origin |
| OpenSpec | prove-redis-readers-by-pointer | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/12 | pr-host |
| CI | build 33965459118 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965459118/job/101304674659 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
- [core_cache_redis_in-tree-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-verity-redis-reader/openspec/changes/prove-redis-readers-by-pointer/proposal.md) — modified

## Follow-up issues
- [ ] [note] [large] Spec `core_cache_redis_in-tree-client` scenario “MGet is available without cache calling it” still says `pkg/cache` uses `Get` per key — GetMany already landed. Not taken.

## How this fits together
Local ticket `2026-09-05-verity-redis-reader` on `master` → PR #12. Propose folded a `Client.New` scenario into `core_cache_redis_in-tree-client`; implement still adds the test.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Is “this issue from another project” upstream #381 item 2 (keep redis readers by pointer)? | assumed — yes; slug plus mutex/readers copy matches. Proceed on that dump. | explore |
| Should we change `pkg/cache/cache.go` anyway? | assumed — no. Code already holds pointers; Bound the ask is a regression test plus a spec scenario. | explore |

## Before merge
- [ ] Add a `Client.New` test that fails if Redis readers are copied by value (upstream #381)

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
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | a05d6c1f16ed9726da33871049ad443e64c0d73b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `master`, fold a `Client.New` pointer-identity scenario into `core_cache_redis_in-tree-client` and add that test; do not rewrite the cache.

Do we have a high-confidence way to reproduce? Yes — `go vet` is clean; `Test_nextReader` passed; `Client.New` already allocates pointers.

Is this the best way to solve the issue? Yes — this fork is not affected; a construction-site test is the ticket.

### Evidence
What I checked:
- OpenSpec change `prove-redis-readers-by-pointer` validates (4/4 artifacts)
- FindSpecHost fold `core_cache_redis_in-tree-client` (high)
- CI Main Process succeeded on run 33965459118; e2e jobs succeeded on run 33965459098

### Rank-up moves
None.
