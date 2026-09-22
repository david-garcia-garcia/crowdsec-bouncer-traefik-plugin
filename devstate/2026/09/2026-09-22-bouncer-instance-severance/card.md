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
In progress. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: 690d71d7
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35755041523 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-22-bouncer-instance-severance pushed | `git` |
| OpenSpec | bouncer-instance-severance | `openspec/` |
| Pull request | none | pr-host |
| CI | build 35755041523 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35755041523 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35755041523 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added

Completed:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified

## Deviations from the ask
- taken:  →  — `` — requirement F3 / T2 subscriber sketch set `crowdsecLapiEnabled: true` with no key, which `ValidateParams` rejects because a true owner flag must Open. Built: `enabled: true`, owner flags false, instance names set (Open-vs-subscribe table).. Requester: not asked.

## Follow-up issues
- [ ] [Stream startup block still means more than "published"](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/knowledge/debt/2026-09-22-stream-startup-block-rethink.md) — `streamStartupBlock` still names stream startup while ready means subscribed client published.

## How this fits together
Ticket 2026-09-22-bouncer-instance-severance on branch 2026-09-22-bouncer-instance-severance targeting master; PR no PR yet; CI build 35755041523 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35755041523.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which package owns the dual LAPI/AppSec slot tables and Publish/Subscribe API? | additive asked — new subsystem in scope (“Named LAPI and AppSec slots”, Late bind); criterion names publish/subscribe | assumed — `pkg/instance` owns both slot tables and Publish/Subscribe/Clear; `plugin.go` orchestrates only; tests colocated under that package. | implement |

## Before merge
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 7 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 690d71d7e4a48458f01171729303a124d60f337a | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 690d71d7e4a48458f01171729303a124d60f337a)

### Rank-up moves
None.
