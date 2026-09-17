Developer review: needs changes — 2026-09-06T15:41:14Z

[sgsi-dev-ticket-status:2026-09-06-upstream-370-stream-poll-lease-interval-one]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/lapi/client_stream_test.go` adds `TestHandleStreamCacheIntervalOneStoresLease`: with `updateInterval` 1, a stream miss stores cache key `updated` and a second poll skips LAPI. Spec `core_plugin_lapi_stream-lease` lives under `openspec/specs/`.

**End users.** None.

## Motivation
On `master`, no test proves that `updateIntervalSeconds: 1` stores stream poll lease key `updated`. Upstream #370 used TTL 0, which never stores. Without this test a regression polls LAPI every tick on multi-instance deploys.

## Merge readiness
Product tests and spec landed. e2e docker + pester failed twice with no test-results.xml (Pester did not start). Not ready for review until that check is green.

Priority: P3 — test coverage; no current operator or end-user harm on the fork.
Reviewed head: ccca343
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | e2e docker + pester failed |
| CI proof | 2/6 | Main Process and mock e2e succeeded; docker Pester failed |
| Local tests proof | N/A | Remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-370-stream-poll-lease-interval-one pushed | git push |
| OpenSpec | stream-poll-lease-interval-one (archived) | openspec/changes/archive/2026-09-06-stream-poll-lease-interval-one/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/47 | pr-host List |
| CI | build 34042707208 failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042707208 | e2e docker + pester: no test-results.xml |
| Local tests | passed | go test ./pkg/lapi/ -count=1 |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_stream-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/openspec/changes/archive/2026-09-06-stream-poll-lease-interval-one/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Upstream #370 add-tests → PR #47 → interval-1 lease unit test and spec archived → Main Process and mock e2e green; docker Pester did not write results.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should tests cover Redis backend explicitly, or is in-memory cache enough to prove lease storage at interval 1? | assumed — in-memory only. | explore |
| Where does the interval-1 lease test live? | assumed — pkg/lapi/client_stream_test.go. | explore |
| Must the test wait for TTL expiry, or is key present plus second call skips LAPI enough? | assumed — no sleep. | explore |

## Before merge
- [ ] [P3] Green e2e (docker + pester): https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042707208/job/101512251944 — annotation `no test-results.xml (Pester did not write results)`. Unrelated to the unit test; Main Process succeeded.
- [x] Pull request retitled ✅ test(lapi): prove stream poll lease stores when interval is 1
- [x] Archive: `openspec/specs/core_plugin_lapi_stream-lease/spec.md`
- [x] Implement: TestHandleStreamCacheIntervalOneStoresLease

## Findings
- [[P3] e2e docker + pester](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042707208/job/101512251944) — FIX — Pester wrote no test-results.xml on two consecutive runs. Path: `.github/workflows/e2e.yml`.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/devstate/2026/09/2026-09-06-upstream-370-stream-poll-lease-interval-one/codereview_standards.md) — 1 total, 0 pending, 1 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/devstate/2026/09/2026-09-06-upstream-370-stream-poll-lease-interval-one/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/devstate/2026/09/2026-09-06-upstream-370-stream-poll-lease-interval-one/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/devstate/2026/09/2026-09-06-upstream-370-stream-poll-lease-interval-one/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/devstate/2026/09/2026-09-06-upstream-370-stream-poll-lease-interval-one/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | ccca34316d7ac8781779a984d7d05664e8fd3066 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: prove the existing lease floor with an in-memory miss→store test.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/lapi/ -count=1 -run TestHandleStreamCacheIntervalOneStoresLease` passed locally and Main Process CI succeeded.

Is this the best way to solve the issue? Yes — add-tests matches `present-fixed-unproven`.

### Evidence
What I checked:
- Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042707277
- e2e mock success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042707208/job/101512252110
- e2e docker + pester failure (no XML) https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042707208/job/101512251944
- Local `go test ./pkg/lapi/ -count=1` passed

### Rank-up moves
None.
