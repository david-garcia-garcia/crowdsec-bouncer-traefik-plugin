## Motivation
Operators cannot compose skip, ban, and captcha on one request matcher. Dest splits that job across two first-match-wins bypass lists (`bouncerLapiBypassRules`, `bouncerAppsecBypassRules`) plus `bouncerDecisionHeader` exact trimmed `b`/`c` that still merges after lookup.

A healthz skip, a header force-ban, and a captcha-without-lookup cannot live on one row. Forced `c` still consults LAPI unless a separate LAPI bypass also matches. Metrics origin for the header path is `plugin:forced_decision`, not a rule name.

Left alone, the two lists and the secret header freeze as the public contract. Operators keep three knobs for one fold, and leftover YAML after a later rename is silent the same way Traefik unused-key decode already drops retired keys.

Priority: P2 — operators cannot compose skip, ban, and captcha on one matcher; leftover old keys are a documented break, not a live outage

## Implementation
One public list `bouncerActionRules` replaces the two bypass lists and the force header. Each row is `httprule.ActionRule` (unique `name`, `action` tokens, embedded predicates). `httprule.NewActionSet` validates names and tokens, then compiles predicates with `httprule.New`. `ValidateParams` wraps `BouncerActionRules: %w` and discards; `bouncer.New` compiles again and stores `*ActionSet`. `Set.Match` stays first-wins boolean; `Matching` returns every hit.

After trusted-IP, `foldActionRules` ORs every match: any `ban` remediates immediately with origin `plugin:rules:<first ban name>` and closed header reason `rules`. Else skip-LAPI / skip-AppSec add, and a `captcha` token is a flag. Remaining legs still run. LAPI or AppSec (including fail-closed) bans keep that leg's origin and WARN `ServeHTTP:forcedCaptchaSuperseded` with `name`. Non-empty AppSec `challenge` does not relay over a captcha rule; empty challenge body stays dest fail-closed ban. Force-header helpers and `plugin:forced_decision` are gone. Leftover old YAML never reaches `New`.

## What this changes
**Operators.** Rewrite `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader` onto `bouncerActionRules` (unique `name`, `action` tokens, same predicates; write `^b$` / `^c$` for the old header); leftover old keys are ignored.

**Admin users.** None.

**Developers.** Public Config is `BouncerActionRules` (`[]httprule.ActionRule`); applied plugin ban/captcha origin is `plugin:rules:<name>`; closed remediation reason is `rules`; `httprule.Matching` returns every hit.

**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — operators cannot compose skip, ban, and captcha on one matcher; leftover old keys are a documented break, not a live outage
Reviewed head: 5056e0ce
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36610683310 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-29-bouncer-action-rules pushed | `git` |
| OpenSpec | bouncer-action-rules | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/175 | pr-host |
| CI | build 36610683310 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36610683310 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36610683310 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/archive/2026-09-29-bouncer-action-rules/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/archive/2026-09-29-bouncer-action-rules/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/archive/2026-09-29-bouncer-action-rules/proposal.md) — modified
- [core_plugin_middleware_forced-decision](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/changes/archive/2026-09-29-bouncer-action-rules/proposal.md) — modified

Completed:
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/specs/core_plugin_lapi_usage-metrics/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-29-bouncer-action-rules on branch 2026-09-29-bouncer-action-rules targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/175; CI build 36610683310 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36610683310.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Whether `name` / `action` land on `httprule.Rule` or a wrapper type beside `pkg/httprule`? | additive asked — new authoring fields this change creates; requirement Add `name` and `action` while keeping today's predicates | assumed — wrapper (Name, Action, embedded `httprule.Rule` predicates). `Rule` stays predicates-only. Config slice type carries the wrapper. httprule does not interpret action tokens. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_standards.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_security.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_performance.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-29-bouncer-action-rules/devstate/2026/09/2026-09-29-bouncer-action-rules/codereview_coverage.md) — 4 total, 0 pending, 4 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 7 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 5056e0ce77dfafbd9a4e096212a7edfdef72db40 | Card must match the branch you measured |

### Stored data model
None.
