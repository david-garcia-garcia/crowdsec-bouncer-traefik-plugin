Developer review: in progress — 2026-09-05T07:03:23.8442801Z

## What this changes
**Operators.** None. (`redisCache*` keys are unchanged versus `master`.)

**Admin users.** None.

**Developers.** Redis cache uses in-tree `pkg/simpleredis` (simpleredis PR #8 pool + RESP + `MGet`). `pkg/cache` holds clients by pointer. Mock e2e Redis parses RESP. Real-stack e2e adds Dragonfly and `redis_cache.Tests.ps1`.

**End users.** None.

## Motivation
On `master` the Redis cache still depends on published `simpleredis` v1.0.12 (one TCP dial per command, inline protocol). There is no real-stack e2e against a functional Redis-protocol backend. Without this PR the plugin cannot take PR #8’s pool/`MGet` client in-tree, and Dragonfly cache behaviour stays untested.

## Merge readiness
Apply is on the branch; CI for this head is still running. 4 phases remain after implement.

Priority: P3 — tests and in-tree client packaging; no current public-contract break claimed
Reviewed head: fe5da7e
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Local pkg tests passed; CI in progress |
| CI proof | 3/6 | Main and E2E in progress on fe5da7e |
| Local tests proof | N/A | Remote PR; CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-integrate-redis-backend pushed | `git` / origin |
| OpenSpec | in-tree-simpleredis-dragonfly-e2e | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/5 | pr-host |
| CI | build 33951488186 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951488186 | GitHub Actions Main; E2E https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951488135 |
| Local tests | passed | `go test ./pkg/...` (cache + simpleredis ok). Root `TestBouncerFileLogging*` failed on Windows file-lock cleanup, unrelated |
| PR comments | no comments | none |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_cache_redis_in-tree-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-integrate-redis-backend/openspec/changes/in-tree-simpleredis-dragonfly-e2e/proposal.md) — added
- [build_e2e_mock_redis-resp](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-integrate-redis-backend/openspec/changes/in-tree-simpleredis-dragonfly-e2e/proposal.md) — added
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-integrate-redis-backend/openspec/changes/in-tree-simpleredis-dragonfly-e2e/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
PR #5 apply: `pkg/simpleredis` from f8801cc, mock RESP, Dragonfly Pester. CI still running on fe5da7e.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Where does the in-tree client live? | assumed — `pkg/simpleredis` | implement |
| Copy sources vs `replace` to the PR branch? | assumed — copy PR #8 sources into the module | implement |
| Must `pkg/cache` call `MGet` now? | assumed — no; ship `MGet` on the package only | implement |
| How to stop copying `SimpleRedis` by value? | assumed — store `*simpleredis.SimpleRedis` | implement |
| Dragonfly image and tag? | assumed — `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2` | implement |
| What does functional redis e2e assert? | assumed — live-mode redisCache against Dragonfly; survive Traefik restart | implement |
| Must mock e2e Redis keep passing after RESP? | assumed — yes; parse RESP arrays in `serveRedis` | implement |
| Who owns the client address in tests? | assumed — Traefik forwarded headers + plugin trusted IPs | implement |
| Pin Dragonfly in operator examples? | assumed — no | implement |

## Before merge
- [ ] Green CI on PR #5 (Main + E2E)
- [x] Land in-tree simpleredis from PR #8 and Dragonfly real-stack e2e

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
| Specs in this PR | 2 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | fe5da7ee79d5e8a5de165fe25902d0d3222014cc | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: In-tree PR #8 client instead of an untagged `replace`, with Dragonfly e2e instead of mock-only Redis.

Do we have a high-confidence way to reproduce? Yes, `go test ./pkg/simpleredis ./pkg/cache` and Pester `redis_cache.Tests.ps1`.

Is this the best way to solve the issue? Yes versus `master`: Yaegi can load `pkg/simpleredis` from the plugin tree.

### Evidence
What I checked:
- `go test ./pkg/...` passed (simpleredis fake-redis suite + cache round-robin)
- `go.mod` no longer requires `github.com/maxlerebourg/simpleredis`
- CI Main 33951488186 and E2E 33951488135 in progress on fe5da7e

### Rank-up moves
None.
