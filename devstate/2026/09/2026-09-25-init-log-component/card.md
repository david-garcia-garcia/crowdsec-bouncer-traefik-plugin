## Motivation
Plugin construction at DEBUG currently logs each trusted address or CIDR as it is inserted into a Checker. Those inserts fire when validateParamsIPs builds (and discards) a Checker for `BouncerForwardedHeadersTrustedIPs` and `BouncerClientTrustedIPs`, then again when `bouncer.New` builds the hop pool and the client pool. Operators who turn on DEBUG to see how trust is configured therefore get one line per entry (`IP is trusted` with `ip=`, `IP network is trusted` with `network=`), and the same range can appear twice because validate and New both construct Checkers.

The construct-time DEBUG `Bouncer initialized` line carries no network attributes, so it does not show the two pools. Every logger also stamps slog `component` as `CrowdsecBouncerTraefikPlugin`, which is too long to scan.

Left alone, DEBUG init stays a per-CIDR spray instead of one line that names both trusted-IP config slices, and dashboards that filter on `component` keep that long identifier. Production traffic, trust membership, and public config keys are unchanged; the cost is operator-log clarity only.

Priority: P3 — operator-log clarity with no current user or operator harm

## Implementation
Stop the two insert Debug calls in `NewChecker` and leave the logger parameter unused so the signature stays. On the existing `bouncer.New` DEBUG `Bouncer initialized`, attach the two Config slices as written: `forwardedHeadersTrustedIPs` from `BouncerForwardedHeadersTrustedIPs` and `clientTrustedIPs` from `BouncerClientTrustedIPs`, including empty lists (nil coerced to empty so JSON is `[]` not `null`); do not merge the pools or rewrite bare hosts. Set `NewWithFormat` `component` to `CrowdsecBouncer`. validateParamsIPs still constructs `NewChecker` so bad CIDRs fail; it no longer emits per-entry lines. Tests lock the new component string, one init record with both attrs, and empty-list attrs including nil; the instance-severance e2e log filter matches `CrowdsecBouncer`.

## What this changes
**Operators.** Filter logs on `component=CrowdsecBouncer` and read both trusted-IP pools on DEBUG `Bouncer initialized` (`forwardedHeadersTrustedIPs`, `clientTrustedIPs`); per-entry `IP is trusted` / `IP network is trusted` lines are gone.
**Admin users.** None.
**Developers.** Construction DEBUG `Bouncer initialized` must carry those two slice attrs as written, and every `NewWithFormat` logger must stamp `component=CrowdsecBouncer`.
**End users.** None.

## Merge readiness
In progress. 1 items remain.

Priority: P3 — operator-log clarity with no current user or operator harm
Reviewed head: fb1bf72c
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Limited confidence |
| CI proof | 3/6 | in progress |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-25-init-log-component pushed | `git` |
| OpenSpec | init-log-component | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/160 | pr-host |
| CI | build 36132080906 in progress | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36132080906/job/108061522676 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [std_go_logger_debug-attrs](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/openspec/changes/init-log-component/proposal.md) — modified
- [std_go_logger_slog-output](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/openspec/changes/init-log-component/proposal.md) — modified


## Deviations from the ask
- taken: rename `component=CrowdsecBouncerTraefikPlugin` to something shorter like CrowdsecBounder. → `CrowdsecBouncer`, the existing type and HTML template name in `pkg/bouncer/bouncer.go`. — `pkg/logger/logger.go` — honouring the typed example would add a misspelled third identity next to the unit already named CrowdsecBouncer; the job is a shorter component, and that name already exists.. Requester: not asked.


## Follow-up issues
- [ ] [Rename `std_go_logger_debug-attrs` to a Trace-named leaf](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/knowledge/debt/2026-09-24-rename-std-go-logger-debug-attrs.md) — domain `debug-attrs` hides Request-path Trace; this run still folds construct-time `Bouncer initialized` attrs onto that leaf.


## How this fits together
Ticket 2026-09-25-init-log-component on branch 2026-09-25-init-log-component targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/160; CI build 36132080906 in progress.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| What shorter slog component string do we use (CrowdsecBounder vs CrowdsecBouncer)? | bounded asked — 9 go-file occurrences enumerated (1 producer, 8 test locks); roots pkg/logger and module-root zzz_bouncer_logging_test.go; Desired names the rename | assumed — CrowdsecBouncer. The ticket typed CrowdsecBounder as an example; the existing type and template name is CrowdsecBouncer. Do not invent a third name. Job (shorter component) survives. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-init-log-component/devstate/2026/09/2026-09-25-init-log-component/codereview_coverage.md) — 2 total, 0 pending, 2 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | fb1bf72c712a8a9152075f98394c8b4f06a0f9a3 | Card must match the branch you measured |

### Stored data model
None.
