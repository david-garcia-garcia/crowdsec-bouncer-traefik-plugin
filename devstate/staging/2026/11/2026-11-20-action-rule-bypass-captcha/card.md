## Motivation
A captcha is a page for a person. A client that is not a browser cannot solve it: a script, a mobile app, or another server calling an API route behind this plugin receives the captcha HTML with HTTP 200 where it expected its API response, and may take that HTML for data. The case that started this was a machine-to-machine integration whose outbound address fell under a CrowdSec `captcha` decision scoped to a whole AS. The decision was aimed at other traffic from that network. The integration stored the captcha page as if it were the API answer and failed on its next call.

The operator had no setting for "on these requests never a captcha, bans still apply". `bouncerClientTrustedIps` exempts an address from every check, AppSec included. `bouncerOriginBasedDecisionRemap` with `captcha: pass` softens one decision origin on a whole router, not on a path. A `bypassLapi` action rule on the path skips the whole decision lookup, so it drops the bans too.

Left alone, any wide captcha decision (range, country, AS) or a failure action `captcha` during an outage breaks every non-browser client of the affected routes for as long as it lasts.

Priority: P2 — real operator pain (API integrations break while a captcha applies) with workarounds that give up more protection than needed

## Implementation
`bouncerActionRules` gains the action token `bypassCaptcha`. `httprule.ActionSet.Fold` names the first matching row with the token in `ActionMatch.BypassCaptchaName` and clears `CaptchaName`, so no captcha rule runs for that request and an AppSec bot-detection challenge is still relayed instead of being left to a captcha that will not be served.

The request path asks one predicate, `bypassesCaptcha(req, match)`, in the three functions through which a captcha reaches the gate: `remediateUnderActionRules` (LAPI decisions and the LAPI failure action; renamed from `remediateWarnCaptchaRuleOnBan`), `captchaAppsecFailure` (AppSec failure action), and `serveAppsecCaptchaGate` (AppSec `captcha` verdict and a captcha form POST). They return `false`, which every caller already reads as "nothing was written, continue", so the request goes on to the next check and then to the backend. No leg is skipped: the decision lookup and the AppSec query still run, and a ban is written as before. The check sits before the captcha downgrade, so a router with no captcha configured lets the request through instead of banning it.

`appliedLAPIRemediation` takes the rule match and keeps a stored ban when `bouncerOriginBasedDecisionRemap` would soften it to a captcha on such a request. Otherwise the ban would become a captcha and then a pass.

The token is read before the single-reading path check that `bypass`, `bypassLapi` and `bypassAppsec` use, by the requester's decision: its `path` regex applies as written. What Traefik does to the path before the plugin was measured on v3.7.11 and v3.7.19 and written to `knowledge/research/ext_traefik_entrypoints_request-path/`. Traefik resolves `..`, `%2e%2e` and `\` (and `..;` from v3.7.18). It forwards `..%2F`, `..%5C`, `..%3B` and double encoding unless the entry point is told to reject them. The README states both lists.

## What this changes
**Operators.** New `bouncerActionRules` action `bypassCaptcha`: on matching requests (for example `path: "^/api/"`) a captcha is never served and the request goes through, while bans still apply; with a `path` rule, set Traefik's `encodedCharacters` entry point options if the backend decodes `%2F`, `%5C` or `%3B` (README "Keep captchas off API routes").
**Admin users.** None.
**Developers.** A function that would serve the captcha gate asks `b.bypassesCaptcha(req, match)` first and returns `false`; `appliedLAPIRemediation`, `captchaAppsecFailure` and `serveAppsecCaptchaGate` take the `httprule.ActionMatch`; `remediateWarnCaptchaRuleOnBan` is now `remediateUnderActionRules`.
**End users.** An API client under a captcha decision gets its API response on the routes the operator exempted, instead of a captcha page.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain (API integrations break while a captcha applies) with workarounds that give up more protection than needed
Reviewed head: 53661509
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
| Branch | 2026-11-20-action-rule-bypass-captcha pushed | `git` |
| OpenSpec | action-rule-bypass-captcha | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/223 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/changes/archive/2026-11-20-action-rule-bypass-captcha/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/changes/archive/2026-11-20-action-rule-bypass-captcha/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/changes/archive/2026-11-20-action-rule-bypass-captcha/proposal.md) — modified

Completed:
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/specs/core_plugin_lapi_origin-based-decision-remap/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-11-20-action-rule-bypass-captcha on branch 2026-11-20-action-rule-bypass-captcha targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/223; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does a ban that `bouncerOriginBasedDecisionRemap` softens to a captcha pass on a `bypassCaptcha` request? | bounded asked — changes `appliedLAPIRemediation`, 2 call sites found in `pkg/` and root `*.go`, both migrated here; requirement Desired "a ban softened to a captcha … stays a ban". | assumed — no, it stays a ban. Proposed in chat and not objected to; not in the caller's last message word for word. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_standards.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_nitpicks.md) — 1 total, 0 pending, 1 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_security.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-action-rule-bypass-captcha/devstate/staging/2026/11/2026-11-20-action-rule-bypass-captcha/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 6 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 53661509b13b133d04fe285656fbdf5078e04c4d | Card must match the branch you measured |

### Stored data model
None.
