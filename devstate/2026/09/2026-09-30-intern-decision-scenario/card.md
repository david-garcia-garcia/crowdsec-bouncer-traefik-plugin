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
Reviewed head: 4916f41e
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36760236473 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-30-intern-decision-scenario pushed | `git` |
| OpenSpec | intern-decision-scenario | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/178 | pr-host |
| CI | build 36760236473 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36760236473 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36760236473 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/openspec/changes/intern-decision-scenario/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/openspec/changes/intern-decision-scenario/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket #172 on branch 2026-09-30-intern-decision-scenario targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/178; CI build 36760236473 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36760236473.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does raw scenario ride a new `Decision.Scenario` field or another Put argument? | additive incidental — new field on `decisionstore.Decision`; existing `Decision{}` literals keep working (zero value is empty id 0); Unknowns lists the surface, no criterion names field vs extra argument | assumed — add `Scenario` on `decisionstore.Decision`. `streamPutItem` copies LAPI `item.Scenario`. Grow unexported `liveResult` with a scenario string so `memoLive` Puts it. Do not add a parallel Put argument. | explore |


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
| Reviewed head | 4916f41e1f020cf02b43fa1e7a167088f589b633 | Card must match the branch you measured |

### Stored data model
None.
