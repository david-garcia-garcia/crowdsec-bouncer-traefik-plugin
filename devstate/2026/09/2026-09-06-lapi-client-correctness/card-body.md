Developer review: in progress — 2026-09-06T15:10:00Z

## What this changes
**Operators.** Live mode now honors `crowdsecLapiFailureAction` when header-scope LAPI queries fail (not only IP lookup errors); stream health no longer races overlapping polls that could mask LAPI failures.

**Admin users.** None.

**Developers.** `pkg/lapi` adds `streamPollMu` for serialized stream polls, clears the `updated` lease on stream GET failure, hardens `crowdsecQuery` against nil transport responses with alone-mode POST body replay on 401, and propagates scope errors from `mergeLiveScope`/`LiveLookup`; new `client_correctness_test.go` covers health thresholds, JSON apply, transport errors, 401 retry, and scope failures.

**End users.** None.

## Motivation
On `master`, `pkg/lapi` races concurrent stream polls that can mask LAPI failures, drops alone-mode POST bodies on 401 retry, and fail-opens live header-scope query errors — leaving bans unenforced. Transport handling is unsafe to maintain. Without this change those defects remain in production paths.

## Merge readiness
Implement complete; codereview not started. 0 task groups remain in `tasks.md`.

Priority: P1 — scope fail-open and alone-mode POST retry make production enforcement unsafe today.
Reviewed head: 99a1ddb
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Local tests passed; CI pending |
| CI proof | 3 | pending on head 99a1ddb |
| Local tests proof | 6/6 | handoff localTests passed |
| Review resolution | 6/6 | OPEN PR #30, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-lapi-client-correctness pushed | git push origin |
| OpenSpec | lapi-client-correctness | openspec validate --strict passed |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/30 | GitHub |
| CI | pending (no checks reported yet) | GitHub PR checks on #30 |
| Local tests | passed | go test ./pkg/lapi/ -count=1 |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_lapi_stream-poll](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/lapi-client-correctness/proposal.md) — added
- [core_plugin_lapi_http-query](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/lapi-client-correctness/proposal.md) — added
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-lapi-client-correctness/openspec/changes/lapi-client-correctness/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Bug-hunt ticket → branch `2026-09-06-lapi-client-correctness` → PR #30 → OpenSpec `lapi-client-correctness` → four product commits in `pkg/lapi` → local tests passed → CI pending on head.

## Decision needed
None.

## Before merge
- [ ] [P2] Run codereview phase (five-axis review)
- [ ] [P2] Wait for CI green on head 99a1ddb
- [x] Implement stream poll serialization and lease failure accounting
- [x] Harden crowdsecQuery and alone-mode POST body replay on 401
- [x] Propagate live header-scope LAPI errors from LiveLookup
- [x] Add httptest coverage per tasks.md §4
- [x] openspec validate lapi-client-correctness --strict

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Inventory at prepare |
| Reviewed head | 99a1ddbbd41f61aa931b8cc5bfced95394950179 | Implement head on branch |

### Stored data model
None.

### Technical review
Best possible solution: dedicated streamPollMu, lease clear on GET failure, crowdsecQuery transport guard with POST replay, and scope error propagation — all within pkg/lapi as scoped.

Do we have a high-confidence way to reproduce? Yes — new httptest suite calls handleStreamTicker, handleStreamCache, crowdsecQuery, and LiveLookup directly; go test ./pkg/lapi/ -count=1 passed.

Is this the best way to solve the issue? Yes — defects share crowdsecQuery and stream poll lifecycle; one change avoids split PRs and matches explore decisions.

### Evidence
What I checked:
- go test ./pkg/lapi/ -count=1 — passed (99a1ddb)
- openspec validate lapi-client-correctness --strict — passed
- GitHub PR #30 checks — pending on 99a1ddb
- origin/master...HEAD diff — pkg/lapi only (+ openspec/devstate bus)

### Rank-up moves
None.
