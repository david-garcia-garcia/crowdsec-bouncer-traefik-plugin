## Motivation
The in-process memory DecisionStore already keeps live keys on `map[string]LiveSlot`. The module graph still required `github.com/leprosus/golang-ttl-map` v1.1.7, a GPL-3.0 package, even though production imports of that store do not use it.

The only remaining importer was `BenchmarkHeapRetained_TTLMap100k`, a retained-heap bench of a store the plugin does not ship. Test depguard allowed that import; Main did not. The vendored copy still carried the GPL-3.0 license with the module.

Left alone, the tree keeps an unused GPL-3.0 test dependency in the module graph and vendor with no runtime effect: a license and internal-clarity gap, not a serving or operator failure. The same leftover was noted as SUP-07 / P-1 at https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1; that URL is a citation of this condition, not a second product change.

Priority: P3 — unused GPL-3.0 test module, no current user or operator harm

## Implementation
The TTLMap bench and its `ttl_map` import were deleted so nothing in the tree still referenced the module. `go mod tidy` and `go mod vendor` then dropped the `go.mod` require, the two `go.sum` lines, the `vendor/modules.txt` entry, and the vendored copy. The Test depguard allow for `github.com/leprosus/golang-ttl-map` was removed so a later re-import fails lint.

`BenchmarkHeapRetained_LiveMap100k` and the live memory store were left as they are. Live `core_plugin_decisionstore_store` already forbids TTL-heap Sets; there is no spec delta. https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 was not merged or cherry-picked; it remains a citation of the same leftover, not work folded in from that fork.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Test and production code must not import `github.com/leprosus/golang-ttl-map`; Test depguard no longer allows it, and the unused GPL-3.0 module is gone from the graph and vendor.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — unused GPL-3.0 test module, no current user or operator harm
Reviewed head: 6b39e08e
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38685196188/job/116258327059 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-15-drop-gpl-test-dep pushed | `git` |
| OpenSpec | drop-gpl-test-dep | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/199 | pr-host |
| CI | build 38685196188 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38685196188/job/116258327059 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38685196188/job/116258327059 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-15-drop-gpl-test-dep on branch 2026-10-15-drop-gpl-test-dep targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/199; CI build 38685196188 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38685196188/job/116258327059.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-15-drop-gpl-test-dep/devstate/2026/10/2026-10-15-drop-gpl-test-dep/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6b39e08e242d8f202860248a6ef98e08bb964841 | Card must match the branch you measured |

### Stored data model
None.
