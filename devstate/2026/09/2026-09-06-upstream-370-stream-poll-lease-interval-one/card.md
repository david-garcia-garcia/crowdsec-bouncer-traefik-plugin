Developer review: needs changes — 2026-09-06T15:27:55Z

[sgsi-dev-ticket-status:2026-09-06-upstream-370-stream-poll-lease-interval-one]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/lapi/client_stream_test.go` adds `TestHandleStreamCacheIntervalOneStoresLease`: with `updateInterval` 1, a stream miss stores cache key `updated` and a second poll does not call LAPI. Spec `core_plugin_lapi_stream-lease` is in the OpenSpec change (not archived yet).

**End users.** None.

## Motivation
On `master`, no test proves that `updateIntervalSeconds: 1` stores stream poll lease key `updated`. Upstream #370 used TTL 0, which never stores, so every instance polls LAPI every tick. Without this test a regression can return silently.

## Merge readiness
Implement landed the test; docker Pester CI failed before writing results. 5 workflow items remain.

Priority: P3 — test coverage; no current operator or end-user harm on the fork.
Reviewed head: a7009c4
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | e2e docker + pester failed |
| CI proof | 2/6 | Main Process and mock e2e succeeded; docker Pester failed |
| Local tests proof | N/A | Remote CI is the proof axis |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-370-stream-poll-lease-interval-one pushed | git push |
| OpenSpec | stream-poll-lease-interval-one | openspec/changes/stream-poll-lease-interval-one/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/47 | pr-host List |
| CI | build 34041797123 failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041797123 | e2e docker + pester: no test-results.xml |
| Local tests | passed | go test ./pkg/lapi/ -count=1 |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_stream-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/openspec/changes/stream-poll-lease-interval-one/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Local assessment for upstream #370 → branch `2026-09-06-upstream-370-stream-poll-lease-interval-one` → PR #47 → unit test landed → docker Pester CI failed (no XML) while Main Process and mock e2e succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should tests cover Redis backend explicitly, or is in-memory cache enough to prove lease storage at interval 1? | assumed — in-memory only. The failure is TTL 0 so Set is a no-op; golang-ttl-map exhibits that. Redis SET EX 0 is out of scope. | explore |
| Where does the interval-1 lease test live? | assumed — new pkg/lapi/client_stream_test.go next to handleStreamCache. Reuse testStreamLAPI. Do not extend TestHandleStreamCacheLeaseHitHydrates. | explore |
| Must the test wait for TTL expiry, or is key present plus second call skips LAPI enough? | assumed — no sleep. After miss path, Get(updated) must succeed and a second handleStreamCache must not increment streamFetches. | explore |

## Before merge
- [ ] [P3] Green CI: e2e (docker + pester) wrote no test-results.xml (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041797123)
- [x] Implement: TestHandleStreamCacheIntervalOneStoresLease; go test ./pkg/lapi/ passed
- [x] Propose: change `stream-poll-lease-interval-one`, spec `core_plugin_lapi_stream-lease`
- [x] Explore: miss→store at interval 1, in-memory, client_stream_test.go
- [x] Prepare: requirement, ticket dump, stub PR

## Findings
- [[P3] e2e docker + pester](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041797123/job/101509787943) — FIX — annotation `no test-results.xml (Pester did not write results)`. Path: `.github/workflows/e2e.yml`. Unit-test change does not start the docker stack.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | a7009c4d45bb85fbe1f956fc79c0167e56c7b988 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: prove the existing lease floor with an in-memory miss→store test; do not change product behavior.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/lapi/ -count=1 -run TestHandleStreamCacheIntervalOneStoresLease` passed locally.

Is this the best way to solve the issue? Yes — add-tests matches `present-fixed-unproven`.

### Evidence
What I checked:
- `go test ./pkg/lapi/ -count=1` passed (local)
- Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041797026
- e2e mock success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041797123/job/101509788315
- e2e docker + pester failure: no test-results.xml https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041797123/job/101509787943

### Rank-up moves
None.
