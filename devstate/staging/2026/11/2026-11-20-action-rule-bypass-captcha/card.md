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
Reviewed head: d1b63a3f
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/44769425194 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-20-action-rule-bypass-captcha pushed | `git` |
| OpenSpec | action-rule-bypass-captcha | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/223 | pr-host |
| CI | build 44769425194 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/44769425194 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/44769425194 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/changes/action-rule-bypass-captcha/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/changes/action-rule-bypass-captcha/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/changes/action-rule-bypass-captcha/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-11-20-action-rule-bypass-captcha on branch 2026-11-20-action-rule-bypass-captcha targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/223; CI build 44769425194 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/44769425194.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does a ban that `bouncerOriginBasedDecisionRemap` softens to a captcha pass on a `bypassCaptcha` request? | bounded asked — changes `appliedLAPIRemediation`, 2 call sites found in `pkg/` and root `*.go`, both migrated here; requirement Desired "a ban softened to a captcha … stays a ban". | assumed — no, it stays a ban. Proposed in chat and not objected to; not in the caller's last message word for word. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 3 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d1b63a3f649251dea3a8d607daf008c729988775 | Card must match the branch you measured |

### Stored data model
None.
