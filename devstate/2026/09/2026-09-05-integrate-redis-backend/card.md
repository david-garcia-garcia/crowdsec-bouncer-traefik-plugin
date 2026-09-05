Developer review: ready for review — 2026-09-05T07:36:02.6179327Z

## What this changes
**Operators.** None. (`redisCache*` keys are unchanged versus `master`.)

**Admin users.** None.

**Developers.** Redis cache uses in-tree `pkg/simpleredis` (simpleredis PR #8 pool + RESP + `MGet`). `pkg/cache` holds clients by pointer. Mock e2e Redis parses RESP. Real-stack e2e adds Dragonfly, `/redis-cache` (2s TTL on `172.19.0.30`), and `/hold-redis` (120s TTL on `172.19.0.32`, Traefik-restart proof).

**End users.** None.

## Motivation
On `master` the Redis cache still depends on published `simpleredis` v1.0.12 (one TCP dial per command, inline protocol). There is no real-stack e2e against a functional Redis-protocol backend. Without this PR the plugin cannot take PR #8’s pool/`MGet` client in-tree, and Dragonfly cache behaviour stays untested.

## Merge readiness
Apply, four-axis review, usage docs, and OpenSpec archive are on the branch. Main, mock e2e, and Docker Pester succeeded on 24dd8b8.

Priority: P3 — tests and in-tree client packaging; no current public-contract break claimed
Reviewed head: 24dd8b8
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | Main and E2E succeeded on 24dd8b8 |
| Local tests proof | N/A | Remote PR; CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-integrate-redis-backend pushed | `git` / origin |
| OpenSpec | in-tree-simpleredis-dragonfly-e2e (archived) | `openspec/changes/archive/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/5 | pr-host |
| CI | build 33952778932 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33952778932 | GitHub Actions Main; E2E https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33952778940 |
| Local tests | passed | `go test ./pkg/...` (cache + simpleredis ok). Root `TestBouncerFileLogging*` failed on Windows file-lock cleanup, unrelated |
| PR comments | no comments | none |
| Security | None. | `devstate/codereview.md` |
| Performance | None. | `devstate/codereview.md` |

## Specs
- [core_cache_redis_in-tree-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-integrate-redis-backend/openspec/changes/archive/2026-09-05-in-tree-simpleredis-dragonfly-e2e/proposal.md) — added
- [build_e2e_mock_redis-resp](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-integrate-redis-backend/openspec/changes/archive/2026-09-05-in-tree-simpleredis-dragonfly-e2e/proposal.md) — added
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-integrate-redis-backend/openspec/changes/archive/2026-09-05-in-tree-simpleredis-dragonfly-e2e/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
PR #5: in-tree `pkg/simpleredis` from f8801cc, mock RESP, Dragonfly Pester with `/hold-redis` and a dedicated hold IP. Catalog archived. CI green on 24dd8b8.

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
None.

## Findings
- [P3] Name `do`/`clean` in pinned `pkg/simpleredis` — skipped; copy stays at simpleredis@f8801cc. Path: `pkg/simpleredis/simpleredis.go:203`. Reply none.
- [P3] Pool-pointer hold uncommented — FIX applied. Path: `pkg/cache/cache.go:116`. Reply none.
- [P3] Mock RESP vs inline uncommented — FIX applied. Path: `tests/e2e/mock/mocklapi/main.go:93`. Reply none.

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
| Reviewed head | 24dd8b8366c592cffb94ef632e2225cd7edb1836 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: In-tree PR #8 client instead of an untagged `replace`, with Dragonfly e2e instead of mock-only Redis. Hold route is `/hold-redis` with IP `172.19.0.32` so Traefik PathPrefix and a leftover 2s Redis key cannot hide a missed `SET EX 120`.

Do we have a high-confidence way to reproduce? Yes, `go test ./pkg/simpleredis ./pkg/cache` and Pester `redis_cache.Tests.ps1`.

Is this the best way to solve the issue? Yes versus `master`: Yaegi can load `pkg/simpleredis` from the plugin tree.

### Evidence
What I checked:
- `go test ./pkg/...` passed (simpleredis fake-redis suite + cache round-robin)
- `go.mod` no longer requires `github.com/maxlerebourg/simpleredis`
- E2E Pester failed on d2124c6 (PathPrefix) and e5a9617 (shared IP / 2s TTL); both fixed
- CI Main 33952778932 success and E2E 33952778940 success on 24dd8b8 (mock e2e job also success)
- Spec map and artifact-name validators OK; change archived as `2026-09-05-in-tree-simpleredis-dragonfly-e2e`

### Rank-up moves
None.
