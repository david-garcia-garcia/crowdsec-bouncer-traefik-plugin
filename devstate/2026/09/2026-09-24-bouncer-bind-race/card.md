## Motivation
Per-router bouncer bindings hold LAPI, AppSec, and captcha clients in `atomic.Value` as `*reclaim.Box`. Watch publishes into those fields while `ServeHTTP` Unboxes the stored pointer and reads `Box.Value` with no sync.

After the first publish, `storeBinding` reused the same Box and assigned `boxed.Value = value`. Concurrent Unbox could see a torn `any` (panic on the request path, which has no recover) or a nil/stale client (wrong failure action or LAPI mode). Yaegi still requires the stored concrete type to stay `*reclaim.Box`.

Leaving that in-place mutation races production traffic whenever an owner republishes while requests are in flight.

Priority: P1 — production is unsafe today on concurrent bind update vs ServeHTTP

## Implementation
`storeBinding` always publishes with `dest.Store(&reclaim.Box{Value: value})` and no longer mutates an already-published Box. Receive* feeders, Unbox, and Watch stay unchanged. Focused concurrent Unbox-vs-Store and new-Box-pointer tests land in `pkg/bouncer`. Usage Gotchas on instance-slots and std_go_reclaim name the immutable-publish rule. The explore-proposed `watchInto` companion stays deliberately unbuilt.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Watcher bindings that Store into `atomic.Value` must publish a new `*reclaim.Box` on every update; never assign `Box.Value` in place on a Box already Loadable by Unbox.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P1 — production is unsafe today on concurrent bind update vs ServeHTTP
Reviewed head: 902c8f28
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions?query=branch%3A2026-09-24-bouncer-bind-race |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-bouncer-bind-race pushed | `git` |
| OpenSpec | bouncer-bind-immutable-box | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/143 | pr-host |
| CI | build 35975143573+35975143577 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions?query=branch%3A2026-09-24-bouncer-bind-race | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions?query=branch%3A2026-09-24-bouncer-bind-race |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/openspec/changes/archive/2026-09-24-bouncer-bind-immutable-box/proposal.md) — modified

Completed:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified


## Deviations from the ask
- proposed: Affected lists only `pkg/bouncer/bouncer.go` (`storeBinding` and its three Receive* callers). → also change `pkg/reclaim/zzz_alias_test.go` `watchInto` to `Store` a new `*Box` each update (same publish shape). — `pkg/reclaim/zzz_alias_test.go` — Unknowns asked whether other watchers mutate `Box.Value`; this test helper does, and leaving it teaches the race. Bounded incidental companion to the named fix.. Awaiting the requester.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-bouncer-bind-race on branch 2026-09-24-bouncer-bind-race targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/143; CI build 35975143573+35975143577 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions?query=branch%3A2026-09-24-bouncer-bind-race.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_standards.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_spec.md) — 2 total, 0 pending, 0 completed, 2 skipped
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_scope.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_performance.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/devstate/2026/09/2026-09-24-bouncer-bind-race/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 902c8f280a16c1799ba1a661371eda83afd39fb2 | Card must match the branch you measured |

### Stored data model
None.
