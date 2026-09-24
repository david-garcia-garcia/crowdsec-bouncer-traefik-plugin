## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: e8ee06b3
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35971965703 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-bouncer-bind-race pushed | `git` |
| OpenSpec | bouncer-bind-immutable-box | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/143 | pr-host |
| CI | build 35971965703 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35971965703 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35971965703 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-bouncer-bind-race/openspec/changes/bouncer-bind-immutable-box/proposal.md) — modified


## Deviations from the ask
- proposed: Affected lists only `pkg/bouncer/bouncer.go` (`storeBinding` and its three Receive* callers). → also change `pkg/reclaim/zzz_alias_test.go` `watchInto` to `Store` a new `*Box` each update (same publish shape). — `pkg/reclaim/zzz_alias_test.go` — Unknowns asked whether other watchers mutate `Box.Value`; this test helper does, and leaving it teaches the race. Bounded incidental companion to the named fix.. Awaiting the requester.

Implement left task 2.1 / `watchInto` unbuilt per human override (Requester not asked; deviations.md stays `[ ] proposed`). Local `go test -race` skipped: no gcc/cgo on implement host; CI Race detector succeeded.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-bouncer-bind-race on branch 2026-09-24-bouncer-bind-race targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/143; CI build 35971965703 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35971965703.

## Explore Decisions
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e8ee06b303b8dc0ed45075944cad7c42ce72ea81 | Card must match the branch you measured |

### Stored data model
None.
