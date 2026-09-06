Developer review: in progress — 2026-09-06T15:15:00Z

## What this changes
**Operators.** Live mode now honors `crowdsecLapiFailureAction` when header-scope LAPI queries fail (not only IP lookup errors); stream health no longer races overlapping polls that could mask LAPI failures; active IP bans still apply when a scope query fails.

**Admin users.** None.

**Developers.** `pkg/lapi` adds `streamPollMu` for serialized stream polls, clears the `updated` lease on stream GET failure, hardens `crowdsecQuery` against nil transport responses with alone-mode POST body replay on 401, propagates scope errors from `mergeLiveScope`/`LiveLookup` while preserving active IP remediation on scope failure; new `client_correctness_test.go` covers health thresholds, JSON apply, transport errors, 401 retry, scope failures, and IP-ban preservation.

**End users.** None.

## Motivation
On `master`, `pkg/lapi` races concurrent stream polls that can mask LAPI failures, drops alone-mode POST bodies on 401 retry, and fail-opens live header-scope query errors — leaving bans unenforced. Transport handling is unsafe to maintain. Without this change those defects remain in production paths.

## Merge readiness
Codereview complete; all hard findings fixed. 0 open axis items. CI pending on head 6fb6359.

Priority: P1 — scope fail-open and alone-mode POST retry make production enforcement unsafe today.
Reviewed head: 6fb6359
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Local tests passed; CI pending |
| CI proof | 1 | pushed; checks not seen on head 6fb6359 |
| Local tests proof | 6/6 | go test ./pkg/lapi/ -count=1 passed after codereview fixes |
| Review resolution | 6/6 | OPEN PR #30, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-lapi-client-correctness pushed | git push origin |
| OpenSpec | lapi-client-correctness | openspec validate --strict passed |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/30 | GitHub |
| CI | not seen on head 6fb6359 | GitHub PR checks |
| Local tests | passed | go test ./pkg/lapi/ -count=1 |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_lapi_stream-poll](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/lapi-client-correctness/proposal.md) — added
- [core_plugin_lapi_http-query](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/lapi-client-correctness/proposal.md) — added
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/lapi-client-correctness/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Bug-hunt ticket → branch `2026-09-06-lapi-client-correctness` → PR #30 → OpenSpec `lapi-client-correctness` → pkg/lapi fixes + codereview hardening → local tests passed → CI pending on head.

## Decision needed
None.

## Before merge
- [ ] [P2] Wait for CI green on head 6fb6359
- [x] Run codereview phase (five-axis review)
- [x] Fix scope error IP-ban preservation and method comment
- [x] Implement stream poll serialization and lease failure accounting
- [x] Harden crowdsecQuery and alone-mode POST body replay on 401
- [x] Propagate live header-scope LAPI errors from LiveLookup
- [x] Add httptest coverage per tasks.md §4
- [x] openspec validate lapi-client-correctness --strict

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/devstate/2026/09/2026-09-06-lapi-client-correctness/codereview_standards.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/devstate/2026/09/2026-09-06-lapi-client-correctness/codereview_spec.md) — 2 total, 0 pending, 2 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/devstate/2026/09/2026-09-06-lapi-client-correctness/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/devstate/2026/09/2026-09-06-lapi-client-correctness/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/devstate/2026/09/2026-09-06-lapi-client-correctness/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Inventory at prepare |
| Reviewed head | 6fb6359 | Codereview head after fixes |

### Stored data model
None.

### Technical review
Best possible solution: dedicated streamPollMu, lease clear on GET failure, crowdsecQuery transport guard with POST replay, scope error propagation with IP-ban preservation — all within pkg/lapi as scoped.

Do we have a high-confidence way to reproduce? Yes — httptest suite calls handleStreamTicker, handleStreamCache, crowdsecQuery, and LiveLookup directly; go test ./pkg/lapi/ -count=1 passed after codereview fixes.

Is this the best way to solve the issue? Yes — defects share crowdsecQuery and stream poll lifecycle; codereview caught spec gap on active IP ban + scope error path.

### Evidence
What I checked:
- Five-axis codereview on origin/master...HEAD (exclude devstate/.cursor)
- go test ./pkg/lapi/ -count=1 — passed (6fb6359)
- GitHub PR #30 checks — not seen on head 6fb6359

### Rank-up moves
None.
