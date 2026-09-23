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
In progress. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 3a1a7a90
Owner decision: None.

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
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/138 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: knobs table names bounce `enabled` and failure action `crowdsecLapiFailureAction` (AppSec twin). → live dest keys `bouncerEnabled`, `bouncerLapiFailureAction`, `bouncerAppsecFailureAction`. New captcha own-axis keys `captchaEnabled` / `captchaInstanceName`. Owner captcha settings stay `bouncerCaptcha*`. — `pkg/configuration/configuration.go` — dest already renamed those bounce/failure keys in PR 137; honouring the spec spellings would add aliases beside the working surface. Requirement Out of scope already declines renaming dest back.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-23-captcha-leg on branch 2026-09-23-captcha-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/138; CI not seen.

## Explore Decisions
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 3a1a7a907902bf1cfbf491e6ca95f3325cc98231 | Card must match the branch you measured |

### Stored data model
None.
