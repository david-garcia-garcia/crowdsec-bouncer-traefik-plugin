## Motivation
This plugin already posts `dropped` / `request` to CrowdSec LAPI usage-metrics on each remediating drop. Official firewall bouncers also post a `dropped` item whose unit is `byte`. Operators who run `cscli metrics show bouncers` compare those tables.

A ban, unsolved captcha, or AppSec envelope only increments the request series (origin, `ip_type`, remediation). The window never carries a `dropped` / `byte` item, so this plugin reports how many requests it remediates and not how much inbound request weight those drops represent.

Left alone, request counts stay correct, but the table stays incomparable with firewall bouncers that already report bytes. Operators have no signal for remediating request weight from this plugin.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation
At drop time, `recordDropped` takes the inbound request and increments both series: existing `IncDropped` (unit `request`, may label `remediation`) then `IncDroppedBytes` with `EstimatedSize()` (unit `byte`, labels `origin` + `ip_type` only).

`EstimatedSize` sums the live request-target, the server-lifted Host field, each Header map key once plus each value, and declared `ContentLength` when `>= 0` capped at 50 MiB (`50 * 1024 * 1024`). It does not read `Body` and does not reconstruct a wire image. `ContentLength == -1` adds nothing for the body.

Byte window keys share the same counters map; `unit` distinguishes the item. Adds and failed-POST restore saturate at MaxInt64; a zero delta does not create a byte key. Request `+=` and processed atomics stay wrapping.

## What this changes
**Operators.** `cscli metrics show bouncers` now shows a second `dropped` row with unit `byte` (`origin` + `ip_type`) beside the existing request row; no new deploy key.
**Admin users.** None.
**Developers.** Remediating drops must also increment `IncDroppedBytes` from `EstimatedSize()`; the byte item omits `remediation`; those window keys saturate at MaxInt64.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: b04cc8ff
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37098854540 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-03-dropped-bytes pushed | `git` |
| OpenSpec | dropped-bytes | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/182 | pr-host |
| CI | build 37098854540 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37098854540 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37098854540 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/openspec/changes/archive/2026-10-03-dropped-bytes/proposal.md) — modified

Completed:
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/openspec/specs/core_plugin_lapi_usage-metrics/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-03-dropped-bytes on branch 2026-10-03-dropped-bytes targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/182; CI build 37098854540 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37098854540.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which labels does the new `dropped` / `byte` item send? | additive incidental — labels on an item this change creates; no In-scope or criterion line names those labels (Unknowns) | assumed — `origin` + `ip_type` only, same values as the paired request item; omit `remediation` (firewall `dropped` / `byte` shape in `ext_crowdsec_lapi_usage-metrics`) | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/devstate/2026/10/2026-10-03-dropped-bytes/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b04cc8ff04836886f3230a4ee2915884760ebbc0 | Card must match the branch you measured |

### Stored data model
None.
