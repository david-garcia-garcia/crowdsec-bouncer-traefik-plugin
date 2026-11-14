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
In progress. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 340cb698
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-14-lapi-multi-client-ticker pushed | `git` |
| OpenSpec | isolate-lapi-poll-loops-across-clients | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/208 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_stream-single-flight](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/openspec/changes/isolate-lapi-poll-loops-across-clients/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/openspec/changes/isolate-lapi-poll-loops-across-clients/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-11-14-lapi-multi-client-ticker on branch 2026-11-14-lapi-multi-client-ticker targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/208; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which loop shape is yaegi-safe across Clients and still stops on Sleep/Close? | bounded asked — 2 startStreamTicker + 2 startMetricsTicker + 4 stopTicker call sites in pkg/lapi, all migrated here (roots: pkg/**/*.go); Desired "Each Client's stream loop and metrics loop receives only its own ticks and its own stop" | assumed — `time.AfterFunc` poll timer with Reset after work and a stopped flag; no select in pkg/lapi. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 340cb698e46b0da22e0a8377e9f39a62e81c6db3 | Card must match the branch you measured |

### Stored data model
None.
