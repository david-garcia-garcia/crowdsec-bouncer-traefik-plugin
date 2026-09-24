## Motivation
When ServeHTTP remediates, TRACE is the breadcrumb operators use to see why. After IP parse, the first line already logs `ip` and `isTrusted`. Mapped CrowdSec scopes for that request — Country, AS, and the rest of `bouncerDecisionScopeHeaders` — are already collected as `RequestScopeValues` immediately before lookup and passed in. The store then merges Ip, present header-scope keys, and Range membership and returns kind, origin, and originID, not which scope fired.

The remediating TRACE still logs `ip`, leftover `cache=hit`, and remediation letter `t` (or `c`). Those mapped values never appear. Live/none miss uses stem `ServeHTTP:LiveLookup` with `ip` and `isBanned` only — same gap. A Country or AS ban looks identical to an Ip ban. `cache=hit` is also the wrong model: the operator-facing story is a store or live lookup, not a cache.

Left alone, TRACE cannot explain which scoped remediations were in play. Operators keep grepping a `cache` attribute that is not the product contract, and they reconstruct headers by hand to tell a header-scope hit from an IP hit.

Priority: P2 — real operator diagnostic pain, with a workaround or limited blast radius

## Implementation
On the remediating path, TRACE reuses the `RequestScopeValues` map already in hand. A helper appends slog group `scopes` (CrowdSec scope name to header value, names sorted) when that map has entries, and omits the group when it is empty. The store-hit `ServeHTTP` line drops `cache` and keeps `ip` plus `remediation`. `ServeHTTP:LiveLookup` keeps `ip` and `isBanned` and gets the same group. The first breadcrumb (`ip`, `isTrusted`) stays. Lookup still returns kind, origin, and originID — no winner field, no Range CIDR. `handleRemediationServeHTTP` stays `ip` and `remediation`. Tests lock present Country and AS, omitted missing headers, no invented keys, and the LiveLookup line.

## What this changes
**Operators.** Remediating TRACE drops `cache=hit` and, when mapped headers are present, adds slog group `scopes` on `ServeHTTP` and `ServeHTTP:LiveLookup`.
**Admin users.** None.
**Developers.** Remediating TRACE must not include `cache`; it must include group `scopes` for present mapped values. The first `ServeHTTP` breadcrumb still requires `ip` and `isTrusted` and must not require `scopes`.
**End users.** None.

## Merge readiness
In progress. 1 items remain.

Priority: P2 — real operator diagnostic pain, with a workaround or limited blast radius
Reviewed head: bec590bc
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
| Branch | 2026-09-24-remediation-match-trace pushed | `git` |
| OpenSpec | remediation-match-trace | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/152 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [std_go_logger_debug-attrs](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/openspec/changes/archive/2026-09-24-remediation-match-trace/proposal.md) — modified

Completed:
- [std_go_logger_debug-attrs](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/openspec/specs/std_go_logger_debug-attrs/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
- [ ] [Rename `std_go_logger_debug-attrs` to a Trace-named leaf](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/knowledge/debt/2026-09-24-rename-std-go-logger-debug-attrs.md) — live spec and usage leaf still say `debug-attrs` while the unit is Request-path Trace.


## How this fits together
Ticket 2026-09-24-remediation-match-trace on branch 2026-09-24-remediation-match-trace targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/152; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Attribute names, and dump every present `RequestScopeValues` entry versus only the winning scope/value? | additive asked — new slog attributes on a remediating TRACE this change edits; Desired "values of scoped remediations in play (headers, AS, and the other mapped scopes)" | assumed — slog group `scopes` with each present `RequestScopeValues` key (CrowdSec scope name) and its header value. Omit missing headers. Do not add a separate winner field. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_standards.md) — 1 total, 0 pending, 1 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_nitpicks.md) — 2 total, 0 pending, 2 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/devstate/2026/09/2026-09-24-remediation-match-trace/codereview_coverage.md) — 1 total, 0 pending, 0 completed, 1 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | bec590bc480097fa8a62aa4479f341fb68f7b6a8 | Card must match the branch you measured |

### Stored data model
None.
