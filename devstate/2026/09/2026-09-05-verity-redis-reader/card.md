Developer review: in progress — 2026-09-05T12:12:52Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet versus `master`. Explore confirmed `pkg/cache` already holds Redis readers by pointer; the `Client.New` regression test is not landed.

**End users.** None.

## Motivation
On `master`, pooled `SimpleRedis` readers are pointers, but `Test_nextReader` never calls `Client.New`. Without a construction-site test, the copy-by-value pattern from [upstream #381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) can return (go vet `copylocks` on the pool mutex) and this fork would not notice.

## Merge readiness
Explore is done. Stub PR is open. CI is queued. The proving test is not on the branch yet. 1 product item remains.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 732fe09
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress |
| CI proof | 3/6 | Main Process queued |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-verity-redis-reader pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/12 | pr-host |
| CI | build 33965408962 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965408962/job/101304536158 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] Spec `core_cache_redis_in-tree-client` scenario “MGet is available without cache calling it” still says `pkg/cache` uses `Get` per key — GetMany already landed. Not taken.

## How this fits together
Local ticket `2026-09-05-verity-redis-reader` on `master` → PR #12. Explore measured that this fork is not affected; a `Client.New` test is the remaining proof.

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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 732fe09ddc3bb9a066d49e4bf08b3b3ea8a33509 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `master`, no product delta yet; fold a `Client.New` pointer-identity scenario into `core_cache_redis_in-tree-client` and add that test.

Do we have a high-confidence way to reproduce? Yes — `go vet ./pkg/cache/` is clean; `go test ./pkg/cache/` passed including `Test_nextReader`; `Client.New` allocates `&simpleredis.SimpleRedis{}`.

Is this the best way to solve the issue? Yes — this fork is not affected; a construction-site test is the ticket.

### Evidence
What I checked:
- `go vet ./pkg/cache/ ./pkg/simpleredis/` (no output, success)
- `go test ./pkg/cache/ -count=1` passed
- Spec `openspec/specs/core_cache_redis_in-tree-client/spec.md` already requires pointer storage; no `Client.New` scenario
- CI Main Process queued on run 33965408962

### Rank-up moves
None.
