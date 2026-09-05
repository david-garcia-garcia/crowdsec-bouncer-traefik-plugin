Developer review: in progress — 2026-09-05T12:10:31Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet versus `master`. Branch only has the ticket bus; the Redis-reader pointer regression test is not landed.

**End users.** None.

## Motivation
On `master`, `pkg/cache` already stores pooled `SimpleRedis` readers as pointers, but `Test_nextReader` never calls `Client.New`. Without a construction-site test, the copy-by-value pattern from [upstream #381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) can return (go vet `copylocks` on the pool mutex) and this fork would not notice.

## Merge readiness
Prepare is done. Stub PR is open. The proving test is not on the branch yet. 1 item remains for this phase's intent; remaining workflow work is still ahead.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 6e0fc3f
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Pushed; CI not seen |
| CI proof | 1/6 | Pushed; CI not seen |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-verity-redis-reader pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/12 | pr-host Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-05-verity-redis-reader` on `master` opened stub PR #12 so this card has a durable host. CI has not been measured yet.

## Decision needed
None.

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
| Reviewed head | 6e0fc3fe5bdfef3d4bf798a556c5ab32b3ed0244 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `master`, no product delta yet; the needed proof is a `Client.New` pointer-identity test, not a cache rewrite.

Do we have a high-confidence way to reproduce? Yes, `go vet` copylocks on a value copy of `SimpleRedis`, and pointer inequality if `nextReader` returns a struct copy.

Is this the best way to solve the issue? Yes — this fork already holds pointers; a construction-site test is the ticket.

### Evidence
What I checked:
- `pkg/cache/cache.go` `redisCache.readers` is `[]*simpleredis.SimpleRedis`; `New` appends `&simpleredis.SimpleRedis{}` (worktree `4c07224` / HEAD `6e0fc3f`)
- `pkg/cache/cache_test.go` `Test_nextReader` uses pointer identity but does not call `Client.New`
- Upstream issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381 (GitHub MCP `issue_read`)
- Product diff `origin/master...HEAD` excluding destate is empty

### Rank-up moves
None.
