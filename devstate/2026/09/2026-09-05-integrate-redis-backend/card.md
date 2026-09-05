Developer review: in progress — 2026-09-05T06:53:36.1268001Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore recorded: copy simpleredis PR #8 into `pkg/simpleredis`, pointer-hold the pool client, RESP-fix mock Redis, add Dragonfly to real-stack e2e. No product code versus `master` yet.

**End users.** None.

## Motivation
On `master` the Redis cache still depends on published `simpleredis` v1.0.12 (one TCP dial per command, inline protocol). There is no real-stack e2e against a functional Redis-protocol backend. Without this PR the plugin cannot take PR #8’s pool/`MGet` client in-tree, and Dragonfly cache behaviour stays untested.

## Merge readiness
Explore written; propose has not started. 6 phases remain.

Priority: P3 — tests and in-tree client packaging; no current public-contract break claimed
Reviewed head: 779925c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Branch pushed; CI not measured on this head |
| CI proof | 1/6 | Pushed; CI not seen for 779925c |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-integrate-redis-backend pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/5 | pr-host |
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
Local ticket from `origin/master`; stub PR #5. Explore assumed in-tree `pkg/simpleredis`, Dragonfly `v1.40.2`, mock RESP, no `MGet` in cache yet.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Where does the in-tree client live? | assumed — `pkg/simpleredis` | explore |
| Copy sources vs `replace` to the PR branch? | assumed — copy PR #8 sources into the module | explore |
| Must `pkg/cache` call `MGet` now? | assumed — no; ship `MGet` on the package only | explore |
| How to stop copying `SimpleRedis` by value? | assumed — store `*simpleredis.SimpleRedis` | explore |
| Dragonfly image and tag? | assumed — `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2` | explore |
| What does functional redis e2e assert? | assumed — live-mode redisCache against Dragonfly; survive Traefik restart | explore |
| Must mock e2e Redis keep passing after RESP? | assumed — yes; parse RESP arrays in `serveRedis` | explore |
| Who owns the client address in tests? | assumed — Traefik forwarded headers + plugin trusted IPs | explore |
| Pin Dragonfly in operator examples? | assumed — no | explore |

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
| Reviewed head | 779925c3d6b177e11df1e808c58194f3448d920b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus `master`.

Do we have a high-confidence way to reproduce? Yes, `master` vendors v1.0.12 and real-stack compose has no Redis-protocol service.

Is this the best way to solve the issue? Explore chose in-tree copy over `replace` so Yaegi can load the client from the plugin tree.

### Evidence
What I checked:
- PR #8 `simpleredis.go` on `pool-redis-connections` (`Init`/`Get`/`Set`/`Del`/`MGet`, `sync.Mutex`, RESP writer)
- `pkg/cache/cache.go` value slice of `SimpleRedis`
- Official Dragonfly Docker docs (port 6379); GitHub release `v1.40.2`
- Explore: `devstate/2026/09/2026-09-05-integrate-redis-backend/explore.md`

### Rank-up moves
None.
