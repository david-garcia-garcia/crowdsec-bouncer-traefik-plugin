Developer review: ready for review — 2026-09-05T12:28:34Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `Test_NewKeepsRedisReadersByPointer` in `pkg/cache/cache_test.go` fails if `Client.New` copies pooled `SimpleRedis` readers by value or aliases them. Spec `core_cache_redis_in-tree-client` gains a `Client.New` construction-site scenario. Production `pkg/cache/cache.go` is unchanged (already pointer-safe).

**End users.** None.

## Motivation
On `master`, pooled `SimpleRedis` readers are pointers, but `Test_nextReader` never calls `Client.New`. Without a construction-site test, the copy-by-value pattern from [upstream #381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) can return (go vet `copylocks` on the pool mutex) and this fork would not notice.

## Merge readiness
Ready for review. CI succeeded on this head. No open PR comments.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 0b5105f
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open comments |
| CI proof | 6/6 | Main Process succeeded |
| Local tests proof | N/A | Remote PR; localTests passed |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-verity-redis-reader pushed | `git` / origin |
| OpenSpec | prove-redis-readers-by-pointer (archived) | `openspec/changes/archive/2026-09-05-prove-redis-readers-by-pointer/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/12 | pr-host |
| CI | build 33965992999 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965992999/job/101306106174 | pr-host CI |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | comments: none |
| Security | None. | destate/codereview.md |
| Performance | None. | destate/codereview.md |

## Specs
- [core_cache_redis_in-tree-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-verity-redis-reader/openspec/changes/archive/2026-09-05-prove-redis-readers-by-pointer/proposal.md) — modified

## Follow-up issues
- [ ] [note] [large] Spec `core_cache_redis_in-tree-client` scenario “MGet is available without cache calling it” still says `pkg/cache` uses `Get` per key — GetMany already landed. Not taken.

## How this fits together
Local ticket `2026-09-05-verity-redis-reader` on `master` → PR #12. This fork was not affected by upstream #381 reader copies; `Test_NewKeepsRedisReadersByPointer` is the proof. Main, mock e2e, and Pester e2e succeeded on 0b5105f.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Is “this issue from another project” upstream #381 item 2 (keep redis readers by pointer)? | assumed — yes; slug plus mutex/readers copy matches. Proceed on that dump. | explore |
| Should we change `pkg/cache/cache.go` anyway? | assumed — no. Code already holds pointers; Bound the ask is a regression test plus a spec scenario. | explore |

## Before merge
None.

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
| Reviewed head | 0b5105fcc4eda568069fd3e4485f0dc2feb66bb8 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `master`, a `Client.New` pointer-identity test and a folded spec scenario; production cache unchanged.

Do we have a high-confidence way to reproduce? Yes — the new test fails if New aliases readers or `nextReader` returns a struct copy; `go test ./pkg/cache/` passed; CI Main + both e2e jobs succeeded.

Is this the best way to solve the issue? Yes — this fork is not affected; the test is the proof the ticket asked for.

### Evidence
What I checked:
- `go test ./pkg/cache/ ./pkg/simpleredis/ -count=1` passed
- Four-axis code review: all none
- Devdocs impact: none (usage already says hold by pointer)
- CI Main Process succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965992999/job/101306106174
- e2e mock succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965993015/job/101306106436
- e2e Pester succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965993015/job/101306106314
- Earlier mock e2e failure on 5cb960f (custom-ban-page) did not reproduce on 0b5105f

### Rank-up moves
None.
