Developer review: needs changes — 2026-09-06T15:23:14+00:00

## What this changes
**Operators.** Live mode now honors `crowdsecLapiFailureAction` when header-scope LAPI queries fail (not only IP lookup errors); stream health no longer races overlapping polls that could mask LAPI failures; active IP bans still apply when a scope query fails.

**Admin users.** None.

**Developers.** `pkg/lapi` adds `streamPollMu` for serialized stream polls, clears the `updated` lease on stream GET failure, hardens `crowdsecQuery` against nil transport responses with alone-mode POST body replay on 401, propagates scope errors from `mergeLiveScope`/`LiveLookup` while preserving active IP remediation on scope failure; new `client_correctness_test.go` covers health thresholds, JSON apply, transport errors, 401 retry, scope failures, and IP-ban preservation. `knowledge/devdocs` adds `core_plugin_lapi_stream-poll` and `core_plugin_lapi_http-query` usage packets and updates middleware failure-action guidance. OpenSpec deltas synced to catalog (`core_plugin_lapi_stream-poll`, `core_plugin_lapi_http-query`, `core_plugin_lapi_failure-action`).

**End users.** None.

## Motivation
On `master`, `pkg/lapi` races concurrent stream polls that can mask LAPI failures, drops alone-mode POST bodies on 401 retry, and fail-opens live header-scope query errors — leaving bans unenforced. Transport handling is unsafe to maintain. Without this change those defects remain in production paths.

## Merge readiness
Implementation, archive, devdocs impact, and codereview complete; local lapi tests passed. Main Process CI failed on head 69e4d30 — fix before merge.

Priority: P1 — scope fail-open and alone-mode POST retry make production enforcement unsafe today.
Reviewed head: 69e4d30
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | Main Process CI failed; local lapi tests passed |
| CI proof | 2/6 | build 34041820405 failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041820405/job/101509850472 |
| Local tests proof | 6/6 | go test ./pkg/lapi/ -count=1 passed on head 69e4d30 |
| Review resolution | 6/6 | OPEN PR #30, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-lapi-client-correctness pushed | git push origin |
| OpenSpec | lapi-client-correctness archived | openspec/changes/archive/2026-09-06-lapi-client-correctness |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/30 | GitHub |
| CI | build 34041820405 failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041820405/job/101509850472 | GitHub Actions |
| Local tests | passed | go test ./pkg/lapi/ -count=1 |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_lapi_stream-poll](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/archive/2026-09-06-lapi-client-correctness/proposal.md) — added
- [core_plugin_lapi_http-query](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/archive/2026-09-06-lapi-client-correctness/proposal.md) — added
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/archive/2026-09-06-lapi-client-correctness/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Bug-hunt ticket → branch `2026-09-06-lapi-client-correctness` → PR #30 → OpenSpec `lapi-client-correctness` archived → pkg/lapi fixes + devdocs packets → local lapi tests passed → Main Process CI failed on head 69e4d30 (e2e checks green).

## Decision needed
None.

## Before merge
- [ ] [P1] Fix Main Process CI failure on head 69e4d30
- [x] Run archive phase (spec sync + folder move)
- [x] Run devdocsimpact phase (stream-poll and http-query packets)
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
| Reviewed head | 69e4d300c9b176bef1f42ba918fc0030112ea06a | Card matches branch head after pullrequest |

### Stored data model
None.

### Technical review
Best possible solution: dedicated streamPollMu, lease clear on GET failure, crowdsecQuery transport guard with POST replay, scope error propagation with IP-ban preservation — all within pkg/lapi as scoped.

Do we have a high-confidence way to reproduce? Yes — httptest suite calls handleStreamTicker, handleStreamCache, crowdsecQuery, and LiveLookup directly; go test ./pkg/lapi/ -count=1 passed on head 69e4d30.

Is this the best way to solve the issue? Yes — defects share crowdsecQuery and stream poll lifecycle; devdocs now cover stream poll and HTTP query usage.

### Evidence
What I checked:
- GitHub PR #30 CI on head 69e4d30 — Main Process failure, both e2e checks success
- go test ./pkg/lapi/ -count=1 — passed (69e4d30)
- origin/master merged — already up to date
- PR title updated to gitmoji ready title (drop WIP)

### Rank-up moves
None.
