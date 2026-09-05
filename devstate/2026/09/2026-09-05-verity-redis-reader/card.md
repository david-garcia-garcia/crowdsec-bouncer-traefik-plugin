Developer review: in progress — 2026-09-05T12:18:55Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `Test_NewKeepsRedisReadersByPointer` in `pkg/cache/cache_test.go` fails if `Client.New` copies pooled `SimpleRedis` readers by value or aliases them. OpenSpec change `prove-redis-readers-by-pointer` adds that construction-site scenario to `core_cache_redis_in-tree-client`.

**End users.** None.

## Motivation
On `master`, pooled `SimpleRedis` readers are pointers, but `Test_nextReader` never calls `Client.New`. Without a construction-site test, the copy-by-value pattern from [upstream #381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) can return (go vet `copylocks` on the pool mutex) and this fork would not notice.

## Merge readiness
The proving test is on the branch. Local `go test ./pkg/cache/` passed. CI for this head is still in progress. 1 item remains (green CI on this SHA).

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 5cb960f
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress on this head |
| CI proof | 3/6 | Main Process in progress |
| Local tests proof | N/A | Remote PR; localTests passed |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-verity-redis-reader pushed | `git` / origin |
| OpenSpec | prove-redis-readers-by-pointer | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/12 | pr-host |
| CI | build 33965673833 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965673833/job/101305254466 | pr-host CI |
| Local tests | passed | handoff.yaml localTests; `go test ./pkg/cache ./pkg/simpleredis` |
| PR comments | no comments | comments: none |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
- [core_cache_redis_in-tree-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-verity-redis-reader/openspec/changes/prove-redis-readers-by-pointer/proposal.md) — modified

## Follow-up issues
- [ ] [note] [large] Spec `core_cache_redis_in-tree-client` scenario “MGet is available without cache calling it” still says `pkg/cache` uses `Get` per key — GetMany already landed. Not taken.

## How this fits together
Local ticket `2026-09-05-verity-redis-reader` on `master` → PR #12. Implement added `Test_NewKeepsRedisReadersByPointer`. Waiting on CI for this SHA.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Is “this issue from another project” upstream #381 item 2 (keep redis readers by pointer)? | assumed — yes; slug plus mutex/readers copy matches. Proceed on that dump. | explore |
| Should we change `pkg/cache/cache.go` anyway? | assumed — no. Code already holds pointers; Bound the ask is a regression test plus a spec scenario. | explore |

## Before merge
- [ ] Wait for CI on 5cb960f to succeed
- [x] Add a `Client.New` test that fails if Redis readers are copied by value (upstream #381)

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
| Reviewed head | 5cb960f46685de82f406d626a34176aa66cc4bfc | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `master`, a `Client.New` pointer-identity test plus a folded spec scenario; production cache unchanged.

Do we have a high-confidence way to reproduce? Yes — the new test fails if New aliases readers or `nextReader` returns a struct copy; `go test ./pkg/cache/` passed.

Is this the best way to solve the issue? Yes — this fork is not affected; the test is the proof the ticket asked for.

### Evidence
What I checked:
- `go test ./pkg/cache/ ./pkg/simpleredis/ -count=1` passed
- `go vet ./pkg/cache/` clean
- `Test_NewKeepsRedisReadersByPointer` added in `pkg/cache/cache_test.go`
- CI Main Process in progress on run 33965673833

### Rank-up moves
None.
