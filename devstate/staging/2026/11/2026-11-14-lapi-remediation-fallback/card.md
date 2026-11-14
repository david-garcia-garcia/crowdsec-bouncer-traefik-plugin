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
Reviewed head: 715d9a3f
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43633144425 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-14-lapi-remediation-fallback pushed | `git` |
| OpenSpec | lapi-remediation-fallback | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/205 | pr-host |
| CI | build 43633144425 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43633144425 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43633144425 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/lapi-remediation-fallback/proposal.md) — modified
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/lapi-remediation-fallback/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/lapi-remediation-fallback/proposal.md) — modified
- [core_plugin_lapi_remediation-fallback](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/lapi-remediation-fallback/proposal.md) — added


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-11-14-lapi-remediation-fallback on branch 2026-11-14-lapi-remediation-fallback targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/205; CI build 43633144425 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43633144425.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Where do README, devdocs and the delivery card state the position on `whitelist` / `allow` decisions, and with which references? | additive asked — new documentation text; requirement Desired 5 and "Delivery card (must)" | assumed — README: one paragraph under "## Decisions" (after the scope list) plus the `LapiRemediationFallback` Variables entry, which also says it is not `bouncerLapiFailureAction`. Devdocs: the stream-apply and origin-remap packets. Card: codereview's Delivery axis writes it into `codereview_delivery.md` `## Motivation`. Text in all three: `whitelist` and `allow` are not valid CrowdSec decision types and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW; use parser whitelists or LAPI allowlists (`cscli allowlists`). References: upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402), upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403), upstream PR #433 whitelist part (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433), fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198). Source: requirement.md; human, chat 2026-11-14. Implement wrote the README paragraph (under "## Decisions", after the scope list and header mapping) and the Variables entry, and the same statement in `knowledge/devdocs/core_plugin_lapi_stream-apply.md` and `core_plugin_lapi_origin-based-decision-remap.md`; the card Motivation stays with codereview's Delivery axis. | implement |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 3 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 715d9a3f9382d045165a69d4032ca5b0720065a1 | Card must match the branch you measured |

### Stored data model
None.
