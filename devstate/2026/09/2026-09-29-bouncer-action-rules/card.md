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
Reviewed head: e8a29445
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
| Branch | 2026-09-29-bouncer-action-rules pushed | `git` |
| OpenSpec | bouncer-action-rules | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/175 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/bouncer-action-rules/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/bouncer-action-rules/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/bouncer-action-rules/proposal.md) — modified
- [core_plugin_middleware_forced-decision](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/bouncer-action-rules/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-29-bouncer-action-rules on branch 2026-09-29-bouncer-action-rules targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/175; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Whether `name` / `action` land on `httprule.Rule` or a wrapper type beside `pkg/httprule`? | additive asked — new authoring fields this change creates; requirement Add `name` and `action` while keeping today's predicates | assumed — wrapper (Name, Action, embedded `httprule.Rule` predicates). `Rule` stays predicates-only. Config slice type carries the wrapper. httprule does not interpret action tokens. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e8a2944520bfa5a7b5985e141ba9f96d2c4b5b4d | Card must match the branch you measured |

### Stored data model
None.
