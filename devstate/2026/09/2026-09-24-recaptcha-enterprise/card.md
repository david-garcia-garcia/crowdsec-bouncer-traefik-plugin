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
Reviewed head: 3b9f1066
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
| Branch | 2026-09-24-recaptcha-enterprise pushed | `git` |
| OpenSpec | recaptcha-enterprise | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/149 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_captcha-assessments](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — added
- [core_plugin_middleware_captcha-enterprise-config](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — added
- [core_plugin_middleware_captcha-siteverify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — added
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-recaptcha-enterprise on branch 2026-09-24-recaptcha-enterprise targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/149; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| What Go result does Validate expose for None / Pass / Reject / Error without ServeHTTP branching on provider? | bounded asked — changes existing Validate (bool, error); 1 production caller (ServeHTTP) and 4 tests in pkg/captcha/zzz_validate_body_test.go (roots worktree *.go) | assumed — (Outcome, error) with None, Pass, Reject. Error is the error return. Verifier.Pass stays (bool, error). ServeHTTP switches on Outcome plus widget.retry. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 3 added / 3 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 3b9f106639801475172320551fc133389700f8df | Card must match the branch you measured |

### Stored data model
None.
