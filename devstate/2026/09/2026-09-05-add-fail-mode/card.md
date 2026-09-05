Developer review: in progress — 2026-09-05T13:25:01.129Z

IssueKey: 2026-09-05-add-fail-mode
JobName: 2026-09-05-add-fail-mode

## What this changes
**Operators.** None yet. Proposed keys `lapiFailureAction` and `appsecFailureAction` (default `ban`); three AppSec block bools will be removed.

**Admin users.** None.

**Developers.** OpenSpec change `lapi-appsec-failure-action`: `core_plugin_lapi_failure-action`, `core_plugin_appsec_failure-action`, and a delta on `core_plugin_appsec_bot-detection`. Merged `origin/master` (bot-detection #9).

**End users.** None.

## Motivation
On `master`, LAPI/AppSec unavailability is split across `updateMaxFailure`, live ban-on-error, and three AppSec booleans. Without the two CrowdSec-shaped actions, operators cannot set one fallback per backend.

## Merge readiness
Propose complete; implement not started. 1 item remains.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: 57a6be6
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Specs written; CI in progress or not re-measured after merge |
| CI proof | 3/6 | Checks not re-queried after merge 192a3de |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-fail-mode pushed | git @ 57a6be6 |
| OpenSpec | lapi-appsec-failure-action | openspec/changes/lapi-appsec-failure-action/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/10 | pr-host |
| CI | not seen | not re-measured this phase |
| Local tests | none | handoff.yaml |
| PR comments | no comments | none |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/lapi-appsec-failure-action/proposal.md) — added
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/lapi-appsec-failure-action/proposal.md) — added
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/lapi-appsec-failure-action/proposal.md) — modified

## Follow-up issues
- [ ] [note] [large] Removing the three AppSec block bools is a published-key break. Operators with `false` must set `appsecFailureAction: passthrough`.
- [ ] [note] [large] `updateMaxFailure` kept as the stream counter next to `lapiFailureAction`.

## How this fits together
Ticket on dest `master` after merge (bot-detection). Stub PR 10. Human accepted `LapiFailureAction` / `AppsecFailureAction`. Implement next.

## Decision needed
None.

## Before merge
- [ ] Implement tasks.md
- [ ] Wait for CI on the apply

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 57a6be61a7ca1c81afda0710ca1598ea3d1d72d5 | Card must match the branch you measured |

### Stored data model
Public Traefik plugin config will gain two string enums and drop three bools (not landed yet).

### Technical review
Best possible solution: Two CrowdSec-named actions plus keeping `UpdateMaxFailure` matches dest `master` and the spec; challenge relay from #9 stays.

Do we have a high-confidence way to reproduce? Yes — current bool/counter paths on `master` after merge.

Is this the best way to solve the issue? Yes for the agreed public surface; apply next.

### Evidence
What I checked:
- Merged origin/master 82dc3ce (bot-detection) with research index union
- OpenSpec apply-ready `lapi-appsec-failure-action`
- `AppsecQuery` now returns `(*AppsecResponse, error)` — failure action must not break challenge relay

### Rank-up moves
None.
