Developer review: in progress — 2026-09-06T15:31:15Z

[sgsi-dev-ticket-status:2026-09-06-upstream-370-stream-poll-lease-interval-one]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/lapi/client_stream_test.go` adds `TestHandleStreamCacheIntervalOneStoresLease` (interval 1 stores `updated`, second poll skips LAPI). Hit counter reads use `atomic.LoadInt64`. Spec `core_plugin_lapi_stream-lease` is in the OpenSpec change.

**End users.** None.

## Motivation
On `master`, no test proves that `updateIntervalSeconds: 1` stores stream poll lease key `updated`. Upstream #370 used TTL 0, which never stores. Without this test a regression polls LAPI every tick on multi-instance deploys.

## Merge readiness
Code review complete (one hard finding fixed). New CI queued. 3 workflow items remain.

Priority: P3 — test coverage; no current operator or end-user harm on the fork.
Reviewed head: 28d59b6
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI running after review fix |
| CI proof | 3/6 | Checks queued on 28d59b6 |
| Local tests proof | N/A | Remote CI is the proof axis |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-370-stream-poll-lease-interval-one pushed | git push |
| OpenSpec | stream-poll-lease-interval-one | openspec/changes/stream-poll-lease-interval-one/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/47 | pr-host List |
| CI | build 34042557959 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042557959 | pr-host CI |
| Local tests | passed | go test ./pkg/lapi/ -count=1 |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_stream-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/openspec/changes/stream-poll-lease-interval-one/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Upstream #370 assessment → PR #47 → interval-1 lease test → five-axis review (Standards hard finding fixed) → archive next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should tests cover Redis backend explicitly, or is in-memory cache enough to prove lease storage at interval 1? | assumed — in-memory only. | explore |
| Where does the interval-1 lease test live? | assumed — pkg/lapi/client_stream_test.go. | explore |
| Must the test wait for TTL expiry, or is key present plus second call skips LAPI enough? | assumed — no sleep. | explore |

## Before merge
- [ ] [P3] Green CI on head 28d59b6 (prior docker Pester run wrote no XML)
- [x] Code review: atomic.LoadInt64 for hits; other axes none
- [x] Implement: TestHandleStreamCacheIntervalOneStoresLease
- [x] Propose: change `stream-poll-lease-interval-one`

## Findings
None.

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
| Reviewed head | 28d59b6c90073c16f9d1220b875a1bf730267b7f | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: prove the existing lease floor with an in-memory miss→store test.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/lapi/ -count=1 -run TestHandleStreamCacheIntervalOneStoresLease` passed after the atomic.LoadInt64 fix.

Is this the best way to solve the issue? Yes — add-tests matches `present-fixed-unproven`.

### Evidence
What I checked:
- Five-axis review on origin/master...HEAD excluding devstate
- Standards 1 hard: *hits → atomic.LoadInt64 (ca9fbea)
- Spec/Security/Performance/Dead: none
- Local `go test ./pkg/lapi/ -count=1` passed

### Rank-up moves
None.
