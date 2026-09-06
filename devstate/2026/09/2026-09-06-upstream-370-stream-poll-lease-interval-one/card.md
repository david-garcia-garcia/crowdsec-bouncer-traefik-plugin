Developer review: in progress — 2026-09-06T15:09:59Z

[sgsi-dev-ticket-status:2026-09-06-upstream-370-stream-poll-lease-interval-one]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet versus `master` — explore decided add-tests in `pkg/lapi/client_stream_test.go` for stream poll lease at `updateIntervalSeconds: 1`; no product apply.

**End users.** None.

## Motivation
On `master`, no test proves that `updateIntervalSeconds: 1` stores the stream poll lease key `updated`. Upstream #370 showed TTL `updateInterval - 1` (= 0) never stores that key, so every instance polls LAPI every tick. This fork already floors the duration at 1 second, but a regression could reintroduce that silent failure.

## Merge readiness
Explore complete; propose and implement remain. 7 workflow items remain.

Priority: P3 — test coverage and internal proof; no current operator or end-user harm on the fork.
Reviewed head: 9c5ceda
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no product apply yet |
| CI proof | 3/6 | Checks queued after explore push |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-370-stream-poll-lease-interval-one pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/47 | pr-host List |
| CI | build 34041423782 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041423782 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local assessment for upstream #370 → branch `2026-09-06-upstream-370-stream-poll-lease-interval-one` → stub PR #47 → explore recorded add-tests plan → propose next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should tests cover Redis backend explicitly, or is in-memory cache enough to prove lease storage at interval 1? | assumed — in-memory only. The failure is TTL 0 so Set is a no-op; golang-ttl-map exhibits that. Redis SET EX 0 is out of scope. | explore |
| Where does the interval-1 lease test live? | assumed — new pkg/lapi/client_stream_test.go next to handleStreamCache. Reuse testStreamLAPI. Do not extend TestHandleStreamCacheLeaseHitHydrates. | explore |
| Which spec host owns the lease-duration floor? | assumed — new core_plugin_lapi_* leaf for stream poll lease (not core_plugin_lapi_connection). Propose runs FindSpecHost. | explore |
| Must the test wait for TTL expiry, or is key present plus second call skips LAPI enough? | assumed — no sleep. After miss path, Get(updated) must succeed and a second handleStreamCache must not increment streamFetches. | explore |

## Before merge
- [ ] [P3] Propose OpenSpec change for interval-1 lease tests
- [ ] [P3] Implement tests in `pkg/lapi` proving lease store when `updateIntervalSeconds: 1`
- [x] Explore: miss→store at interval 1, in-memory, client_stream_test.go
- [x] Prepare: requirement, ticket dump, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No spec.md delta yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 9c5ceda342791c680bc18fcb71a8198e9149a2fd | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: add-tests proving the existing floor at interval 1, without changing product behavior on `master`.

Do we have a high-confidence way to reproduce? Yes for the miss→store path: `handleStreamCache` with `updateInterval=1`, mock LAPI via `testStreamLAPI`, assert `Get("updated")` then a second call does not increment `streamFetches`. Test not written yet.

Is this the best way to solve the issue? Yes — add-tests matches assessment `present-fixed-unproven` without changing behavior.

### Evidence
What I checked:
- `pkg/lapi/client_stream.go` lease floor at 1 second (9c5ceda)
- `pkg/lapi/client_range_test.go` lease-hit hydrate uses TTL 60 only (9c5ceda)
- `vendor/github.com/leprosus/golang-ttl-map/map.go` Set returns when ttl == 0 (9c5ceda)
- `pkg/lapi/session_test.go` `testStreamLAPI` mock for stream GET (9c5ceda)

### Rank-up moves
None.
