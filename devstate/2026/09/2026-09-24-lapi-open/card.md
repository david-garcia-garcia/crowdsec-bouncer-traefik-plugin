## Motivation
The Traefik constructor already owns which legs Open. AppSec and captcha each expose a single `Open`. LAPI still exposes two reclaim entry points, and the constructor is the one that picks.

`openOwnedLeg` branches `LapiMode`: stream or alone calls `OpenStream`, otherwise `OpenLive`. Both already do the same reclaim Open — DecisionStore, `OwnershipKey`, `New`, hooks, `bindIdentity`. The only extra line on `OpenStream` is `noteStreamOwner`, and that helper already returns unless mode is stream or alone. `LapiMode` is already on the `Config` that `New` reads for the stream ticker, live lookup, and metrics.

Leaving the split means every production and test caller must choose an entry point that is not a consumer concern. The live catalog still names the pair as the current contract. Stream, live, none, and alone keep working; the leftover axis is a wrong constructor contract, not a runtime failure.

Priority: P3 — internal clarity with no current user or operator harm

## Implementation
One exported `lapi.Open` with the same signature as `appsec.Open` and `captcha.Open`. Its body is the former shared reclaim Open plus `noteStreamOwner` on every mode (still a no-op for live and none). `OpenStream` and `OpenLive` are removed; no aliases. The LAPI own-axis in the constructor is that one call and no longer reads `LapiMode` to pick an entry point. In-package tests retarget to `Open`; function names that still say OpenStream or OpenLive stay as scenario labels. The live LAPI connection and DecisionStore store leaves now promise `Open`. A debt note records an unrelated Windows range-index classification that already failed on dest.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Callers and the live catalog must use one `lapi.Open`; `OpenStream` and `OpenLive` are gone.
**End users.** None.

## Merge readiness
Ready for review. 1 items remain.

Priority: P3 — internal clarity with no current user or operator harm
Reviewed head: 90158e91
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35973777360 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-lapi-open pushed | `git` |
| OpenSpec | one-lapi-open | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/145 | pr-host |
| CI | build 35973777360 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35973777360 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35973777360 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/openspec/changes/one-lapi-open/proposal.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/openspec/changes/one-lapi-open/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
- [ ] [Windows range-index read classifies as unsupported-reply](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/knowledge/debt/2026-09-24-windows-range-index-unreachable.md) — dest Windows `go test ./...` fails `TestApplyRangeBatch_UnreachableReadKeepsSharedIndex` (`redis:unsupported-reply` instead of `ErrUnreachable`).


## How this fits together
Ticket 2026-09-24-lapi-open on branch 2026-09-24-lapi-open targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/145; CI build 35973777360 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35973777360.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-open/devstate/2026/09/2026-09-24-lapi-open/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 90158e917610aa519621ea4b8b1c7e1787d2c24e | Card must match the branch you measured |

### Stored data model
None.
