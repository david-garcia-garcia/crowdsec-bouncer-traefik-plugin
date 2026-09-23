## Motivation
Operators already share one LAPI client or one AppSec client across routers: one middleware Opens and publishes a name; bouncing routers Watch that name and keep bounce policy on the router. Captcha was not in that table.

Each bouncing middleware built its own siteverify client, template, and gate from that router’s `bouncerCaptcha*` copy. There was no `captchaEnabled` or `captchaInstanceName`. `bouncer.New` always constructed a local client, so leftover subscriber keys still owned captcha. Failure action `captcha` was legal when `bouncerCaptchaProvider` was set, not when the router had a captcha instance name. Startup-block 503 covered a missing LAPI or AppSec subscribe only. A holder with bounce off could not publish captcha for others.

Operators who wanted one page, one verifier, and one grace across several routers had to duplicate every captcha key. Those copies drift (different grace, different template, different siteverify timeout). A change to the challenge page meant touching every bouncing middleware. The share-one-client model they already use for LAPI and AppSec stopped at captcha.

Priority: P2 — operator pain with a workaround

## Implementation
Captcha is a third reclaim group beside LAPI and AppSec. The constructor Prepares, Opens, claims, and Watches group `captcha` the same way: `captchaEnabled` owns; `bouncerEnabled` plus a non-empty `captchaInstanceName` bounces. An omitted name fills to the Traefik name only when owned. Default own flag is false; a set provider does not own.

The owner Opens the siteverify client, template, and gate from dest `bouncerCaptcha*` keys. The ownership key is the middleware name plus those instance knobs; slot name, bounce, failure action, remediation header, and startup-block stay off it. Subscribers Watch only. Bounce-only `New` does not construct a local client. Leftover subscriber keys are ignored; owner-style checks run only when `captchaEnabled`.

The Bouncer Stores the published pointer and Loads it on the request path. The remediation header stays on the router and is passed into the challenge page and the solved redirect so a subscriber does not inherit the owner’s header. Startup block on returns 503 for an unpublished subscribed captcha name. Startup block off continues; a captcha verdict with no published client is a ban. Failure action `captcha` is legal when the instance name is ready after owner-fill. In-repo examples and e2e set `captchaEnabled: true` on captcha-serving routes.

## What this changes
**Operators.** YAML that only sets `bouncerCaptchaProvider` no longer owns or serves captcha; set `captchaEnabled: true` on the owner (empty `captchaInstanceName` fills to the Traefik name) and subscribe other routers to that name. Leftover subscriber `bouncerCaptcha*` is ignored. `captcha` on `bouncerLapiFailureAction` / `bouncerAppsecFailureAction` requires that router’s instance name after fill. An unpublished subscribed name is 503 when startup block is on.
**Admin users.** None.
**Developers.** Captcha is a third reclaim value (`Prepare` / `Open` / `Watch`); `bouncer.New` takes `subscribeCaptcha` and Loads the published client. `Client.New`, `ServeHTTP`, and `WriteSolvedRedirect` take the remediation header at the call site, not on the Client. Failure action `captcha` requires an instance name after fill.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — operator pain with a workaround
Reviewed head: 5f0be9a5
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
| Branch | 2026-09-23-captcha-leg pushed | `git` |
| OpenSpec | captcha-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/138 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified
- [core_plugin_middleware_captcha-gate](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/openspec/changes/captcha-leg/proposal.md) — modified


## Deviations from the ask
- taken: knobs table names bounce `enabled` and failure action `crowdsecLapiFailureAction` (AppSec twin). → live dest keys `bouncerEnabled`, `bouncerLapiFailureAction`, `bouncerAppsecFailureAction`. New captcha own-axis keys `captchaEnabled` / `captchaInstanceName`. Owner captcha settings stay `bouncerCaptcha*`. — `pkg/configuration/configuration.go` — dest already renamed those bounce/failure keys in PR 137; honouring the spec spellings would add aliases beside the working surface. Requirement Out of scope already declines renaming dest back.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-23-captcha-leg on branch 2026-09-23-captcha-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/138; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Default of `captchaEnabled` and how existing `bouncerCaptchaProvider`-only YAML migrates? | bounded asked — new own flag plus in-repo operator YAML that today treats provider-set as own; 4 example files and 4 e2e hits (roots: `examples/**`, `tests/**`, `pkg/**`, `*.go` for `bouncerCaptchaProvider`) | assumed — default false, matching `lapiEnabled` / `appsecEnabled`. No implicit own from provider. Single-router operators set `captchaEnabled: true` (empty name fills to the Traefik name). Update those in-repo examples and e2e here. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_standards.md) — 2 total, 0 pending, 2 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-leg/devstate/2026/09/2026-09-23-captcha-leg/codereview_coverage.md) — 2 total, 0 pending, 2 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 7 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 5f0be9a5f3d701190fdab02afbf78f707dbc3149 | Card must match the branch you measured |

### Stored data model
None.
