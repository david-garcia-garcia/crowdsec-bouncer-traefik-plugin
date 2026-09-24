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
Ready for review. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: b170f7e6
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36066689093 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-eucaptcha-provider pushed | `git` |
| OpenSpec | eucaptcha-provider | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/155 | pr-host |
| CI | build 36066689093 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36066689093 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36066689093 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_captcha-enterprise-config](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — modified
- [core_plugin_middleware_captcha-eucaptcha-verify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — added
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — modified


## Deviations from the ask
- taken: eucaptcha beside hcaptcha, recaptcha, turnstile, and custom. → those tokens plus dest's recaptcha-enterprise. — `pkg/configuration/configuration.go validateCaptcha` — dest already owns that token; dropping it would distort the allowlist this change extends.. Requester: not asked.


## Follow-up issues
- [ ] [Provider allowlist lives on captcha-enterprise-config](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/knowledge/debt/2026-09-24-allowlist-on-captcha-enterprise-config.md) — provider allowlist lives on leaf `captcha-enterprise-config`.


## How this fits together
Ticket 2026-09-24-eucaptcha-provider on branch 2026-09-24-eucaptcha-provider targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/155; CI build 36066689093 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36066689093.
Upstream pull request (maxlerebourg tree, not this repo): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Is an empty User-Agent a rejection the same way as an empty client address? | additive asked — new verifier this change creates; Unknowns on requirement.md; Desired names empty address as rejection only | assumed — no. Forward r.UserAgent() including empty string. Do not local-reject empty UA. Official field is necessary but the owner does not state HTTP for empty or missing UA. Empty client address stays a local reject on this verifier. Source knowledge/research/ext_eucaptcha_verify/. | explore |


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
| Reviewed head | b170f7e6c986b0504942475c5a1f0d22788e8d25 | Card must match the branch you measured |

### Stored data model
None.
