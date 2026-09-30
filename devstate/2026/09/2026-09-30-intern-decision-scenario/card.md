## Motivation
Stream and live already receive LAPI `decision.Scenario` on each ban or captcha. `MetricsOrigin` keeps that string only for lists, folding it into origin as `lists:<name>`. For `crowdsec`, `CAPI`, and `cscli`, the raw scenario is discarded before Put. Store `Decision` has no scenario field. The in-memory slot is an 8-byte `LiveSlot` whose packed word holds ASCII kind, origin intern id, and family — one origin intern table, no place for the raw name.

When a stream or live ban arrives with origin `crowdsec` and scenario `ssh-bf`, the store records origin `crowdsec` and the scenario string is gone after pack. Lists keep `lists:firehol_level1` as the origin label but still do not intern `firehol_level1` on its own. Lookup, dropped items, and `active_decisions` still work on kind plus origin; they do not need scenario today. Per-scenario usage metrics later will need that raw name on the live slot, without sending a `scenario` label yet.

Leaving the drop in place does not break current remediations or the origin×family gauge. It leaves nowhere on the existing 8-byte word to recover a scenario id, so a later metrics series would have to reshape the slot or re-learn names pack already threw away.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm

## Implementation
Stream and live copy LAPI `Scenario` onto `decisionstore.Decision` (`streamPutItem`, `liveResult` / `memoLive`). DecisionStore owns a second intern table for that raw name; origins stay folded `MetricsOrigin`, so lists intern twice (`lists:firehol_level1` and `firehol_level1`). Memory re-lays the existing `uint32` to 2-bit kind (0 empty / 1 `t` / 2 `c` / 3 `f`), 12-bit origin, 2-bit family, and 16-bit scenario id; unpack still returns ASCII `t`/`c`/`f`. Origin ids above 4095 pack as 0 with Warn `decisionstore:intern overflow`; scenario table overflow Warns `decisionstore:scenario intern overflow` and packs scenario id 0; kind, family, and TTL stay. Redis and the range blob remain `KindOriginString`. Lookup, `IncDropped`, and `ActiveCounts` stay origin×family; usage-metrics still must not send a `scenario` label.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Put carries `Decision.Scenario` into Scenario intern; `LookupRemediation` still returns kind, origin name, and origin id; usage-metrics still MUST NOT send a `scenario` item label.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: da90fcb7
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36770598229 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-30-intern-decision-scenario pushed | `git` |
| OpenSpec | intern-decision-scenario | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/178 | pr-host |
| CI | build 36770598229 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36770598229 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36770598229 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/openspec/changes/archive/2026-09-30-intern-decision-scenario/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/openspec/changes/archive/2026-09-30-intern-decision-scenario/proposal.md) — modified

Completed:
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/openspec/specs/core_plugin_decisionstore_store/spec.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/openspec/specs/core_plugin_lapi_usage-metrics/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket #172 on branch 2026-09-30-intern-decision-scenario targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/178; CI build 36770598229 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36770598229.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does raw scenario ride a new `Decision.Scenario` field or another Put argument? | additive incidental — new field on `decisionstore.Decision`; existing `Decision{}` literals keep working (zero value is empty id 0); Unknowns lists the surface, no criterion names field vs extra argument | assumed — add `Scenario` on `decisionstore.Decision`. `streamPutItem` copies LAPI `item.Scenario`. Grow unexported `liveResult` with a scenario string so `memoLive` Puts it. Do not add a parallel Put argument. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_dead.md) — 2 total, 0 pending, 2 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-30-intern-decision-scenario/devstate/2026/09/2026-09-30-intern-decision-scenario/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | da90fcb7067ca2c8facbd38f467183f5d0eafda2 | Card must match the branch you measured |

### Stored data model
None.
