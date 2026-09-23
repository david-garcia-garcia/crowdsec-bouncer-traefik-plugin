## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 20db88e2
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35908481284/job/107342045705 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-23-captcha-leg pushed | `git` |
| OpenSpec | captcha-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/138 | pr-host |
| CI | build 9e2773dc7b3a65b6a505c8003e25c4fea1e7e10b succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35908481284/job/107342045705 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35908481284/job/107342045705 |
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
Ticket 2026-09-23-captcha-leg on branch 2026-09-23-captcha-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/138; CI build 9e2773dc7b3a65b6a505c8003e25c4fea1e7e10b succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35908481284/job/107342045705.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Default of `captchaEnabled` and how existing `bouncerCaptchaProvider`-only YAML migrates? | bounded asked — new own flag plus in-repo operator YAML that today treats provider-set as own; 4 example files and 4 e2e hits (roots: `examples/**`, `tests/**`, `pkg/**`, `*.go` for `bouncerCaptchaProvider`) | assumed — default false, matching `lapiEnabled` / `appsecEnabled`. No implicit own from provider. Single-router operators set `captchaEnabled: true` (empty name fills to the Traefik name). Update those in-repo examples and e2e here. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 7 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 20db88e24f7ec1666e804ee4ea066dbf51d4ae71 | Card must match the branch you measured |

### Stored data model
None.
