Developer review: in progress — 2026-09-06T14:58:27Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On master, `plugin.go` `New` can leave LAPI/AppSec reclaim tickers running after a later constructor step fails, and `crowdsecMode: appsec` with AppSec disabled succeeds as a silent pass-through with no CrowdSec enforcement. Without this change, misconfigured routers leak background pollers and can forward traffic with no WAF or LAPI lookup.

## Merge readiness
Not ready for review. Prepare complete; explore is next. Product delta versus `master` is journal only.

Priority: P1 — appsec mode without AppSec enabled is a silent no-enforcement pass-through
Reviewed head: 7a7ffcd
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | CI not seen; no product apply |
| CI proof | 1/6 | pushed; checks not seen |
| Local tests proof | N/A | before implement; remote CI covers proof |
| Review resolution | 6/6 | OPEN PR #31, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-plugin-constructor-rollback pushed | git origin |
| OpenSpec | none | handoff.yaml change |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/31 | pr-host Create |
| CI | not seen | pr-host status pending, 0 checks |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt spec grouped three plugin constructor findings; branch `2026-09-06-plugin-constructor-rollback` from `origin/master`, stub PR #31, requirement written, scope bound to `plugin.go` and constructor tests.

## Decision needed
None.

## Before merge
- [ ] Roll back LAPI/AppSec reclaim holders on constructor failure in `plugin.go` [P2]
- [ ] Reject appsec mode when AppSec is disabled (no pass-through) [P1]
- [ ] Add constructor mode and error-path tests in `plugin_test.go` [P3]
- [x] Stub PR #31 open from `2026-09-06-plugin-constructor-rollback`
- [x] Requirement and ticket dump written under devstate bus

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Journal-only prepare commit |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 7a7ffcdb97ad6e4e4060fe20f9efa2547b0b689b | Card matches measured branch |

### Stored data model
None.

### Technical review
Best possible solution: not merged yet. Requirement points at explicit reclaim drop on partial `New` failure and appsec-mode guard in `plugin.go`.

Do we have a high-confidence way to reproduce? Not yet measured on this branch; sibling findings cite `plugin_test.go` gaps and reclaim holder persistence after failed `appsec.Open`.

Is this the best way to solve the issue? Pending explore. Appsec guard may live in `New` only given scope bound.

### Evidence
What I checked:
- `plugin.go:53-77` constructor open order without rollback
- `pkg/configuration/configuration.go:361` appsec mode LAPI key waiver without AppSec enable requirement
- Grouped bug-hunt findings under `devstate/bug-hunt/2026-09-06/plugin/`
- PR #31 created; CI checks not seen yet

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-plugin-constructor-rollback]
