Developer review: in progress — 2026-09-06T15:13:58Z

[sgsi-dev-ticket-status:2026-09-06-upstream-370-stream-poll-lease-interval-one]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `stream-poll-lease-interval-one` adds spec `core_plugin_lapi_stream-lease` (lease TTL at least 1s when `updateIntervalSeconds` is 1). Tests not applied yet.

**End users.** None.

## Motivation
On `master`, no test or spec proves that `updateIntervalSeconds: 1` stores stream poll lease key `updated`. Upstream #370 used TTL 0, which never stores. This fork already floors the duration; without a spec and test a regression would poll LAPI every tick on multi-instance deploys.

## Merge readiness
Propose complete; implement remains. 6 workflow items remain.

Priority: P3 — spec and tests; no current operator or end-user harm on the fork.
Reviewed head: 2db2508
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; tests not applied |
| CI proof | 3/6 | Checks queued after propose push |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-370-stream-poll-lease-interval-one pushed | git push |
| OpenSpec | stream-poll-lease-interval-one | openspec/changes/stream-poll-lease-interval-one/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/47 | pr-host List |
| CI | build 34041647557 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041647557 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_lapi_stream-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-370-stream-poll-lease-interval-one/openspec/changes/stream-poll-lease-interval-one/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Local assessment for upstream #370 → branch `2026-09-06-upstream-370-stream-poll-lease-interval-one` → stub PR #47 → OpenSpec change `stream-poll-lease-interval-one` → implement tests next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should tests cover Redis backend explicitly, or is in-memory cache enough to prove lease storage at interval 1? | assumed — in-memory only. The failure is TTL 0 so Set is a no-op; golang-ttl-map exhibits that. Redis SET EX 0 is out of scope. | explore |
| Where does the interval-1 lease test live? | assumed — new pkg/lapi/client_stream_test.go next to handleStreamCache. Reuse testStreamLAPI. Do not extend TestHandleStreamCacheLeaseHitHydrates. | explore |
| Must the test wait for TTL expiry, or is key present plus second call skips LAPI enough? | assumed — no sleep. After miss path, Get(updated) must succeed and a second handleStreamCache must not increment streamFetches. | explore |

## Before merge
- [ ] [P3] Implement tests in `pkg/lapi` proving lease store when `updateIntervalSeconds: 1`
- [x] Propose: change `stream-poll-lease-interval-one`, spec `core_plugin_lapi_stream-lease`
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
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 2db2508ab3585efd7cb809e6a8b859393c9b5471 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: spec the existing floor and add an in-memory miss→store test, without changing product behavior on `master`.

Do we have a high-confidence way to reproduce? Yes — `handleStreamCache` with `updateInterval=1` and `testStreamLAPI`. Test not written yet.

Is this the best way to solve the issue? Yes — add-tests matches `present-fixed-unproven`.

### Evidence
What I checked:
- FindSpecHost new `core_plugin_lapi_stream-lease` (2db2508)
- `openspec validate stream-poll-lease-interval-one` passed
- `pkg/lapi/client_stream.go` lease floor unchanged (2db2508)

### Rank-up moves
None.
