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
Reviewed head: e2744040
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
| Branch | 2026-09-24-template-startup-warn pushed | `git` |
| OpenSpec | 2026-09-24-template-startup-warn | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/151 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/openspec/changes/2026-09-24-template-startup-warn/proposal.md) — modified


## Deviations from the ask
- proposed: Check both files when the bouncer is created. → `captcha.Client.New` / `Open` warns for the captcha template; `bouncer.New` warns for the ban template. — `pkg/captcha/captcha.go Client.New, pkg/bouncer/bouncer.go New` — honouring the wording adds a `CaptchaFilePath` check to `bouncer.New`, a unit that does not own captcha, and would warn a bounce-only subscriber whose unused default is `/captcha.html`.. Awaiting the requester.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-template-startup-warn on branch 2026-09-24-template-startup-warn targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/151; CI not seen.

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
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e2744040edb5007c71db3da5fdc680eaca619160 | Card must match the branch you measured |

### Stored data model
None.
