## Motivation
An AppSec rule or hook can answer a request with a captcha instead of a ban (`SetRemediation("captcha")`). `captcha` is one of CrowdSec's four official AppSec remediations (`ban`, `captcha`, `allow`, `challenge` in `crowdsecurity/crowdsec` `pkg/appsec/appsec.go`), and CrowdSec sends it as `{"action":"captcha","http_status":403}` with no page: `GenerateResponse` fills `user_body_content` only for `challenge`. The protocol leaves `ban` and `captcha` to the bouncer's own templates.

The plugin relayed every AppSec action other than `ban` as an envelope. For `captcha` that wrote `http_status` 403 and an empty body, so the visitor saw a blank page instead of a captcha, with `X-Remediation: captcha:appsec`. The router's configured captcha, which already serves LAPI captcha decisions, captcha action rules and the AppSec failure-action captcha, was never used. A custom action such as `SetRemediation("tarpit")` ended the same way, as an empty page. A spec requirement and two tests locked that blank relay in.

Serving the captcha raises a second gap: AppSec judges each request alone. The captcha form posts back to the same URL and goes through AppSec first; a rule that matched the GET but not that POST lets it through to the backend, the answer is never checked, and the captcha cannot be solved.

Upstream references (maxlerebourg/crowdsec-bouncer-traefik-plugin):
- Issue [#357](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/357) — feature request: support AppSec `"action": "captcha"`.
- Issue [#402](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) point 3 — an AppSec `captcha` action is turned into a ban.
- PR [#403](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403) commit 3 — serves the configured captcha for AppSec `captcha`; validates the form POST only when AppSec answers it with `captcha` again.
- PR [#343](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343) — bot detection support: relays `challenge`, bans every other action.
- Issue [#389](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389) — bot-detection challenge never resolved through the plugin (context for #343).
- Issue [#354](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/354) / PR [#428](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/428) — a captcha form submitted again after solving reached the backend; this fork handles it with the `crowdsec_captcha_challenge=v1` marker (#201), which this change reuses.

Priority: P2 — real end-user pain (blank page instead of a captcha) limited to operators who use AppSec `captcha` or custom actions

## Implementation
`applyAppsecServeHTTP` now sends an AppSec `captcha` to the router's existing captcha gate through `serveAppsecCaptchaGate` (metrics origin `appsec`, header `captcha:appsec`, downgrade ban reason `APPSEC`). `handleCaptchaKindServeHTTP` takes the challenge-page header reason and the downgrade ban reason from its caller, so LAPI, rule and failure-action captchas keep their values. With a matched captcha action rule, AppSec `captcha` returns false and the rule's gate serves it, as a non-empty `challenge` already did. An action other than `allow` / `ban` / `captcha` / `challenge` with no `user_body_content` now bans with the new closed reason `appsec-action-empty`; with a body it is still relayed. After AppSec lets a request through on the non-rule path, `serveAppSec` sends a POST carrying `crowdsec_captcha_challenge=v1` to the same captcha gate when the router has a usable captcha client: the token is verified (gate cookie and 302) or a leftover form gets the solved redirect. AppSec still inspects that POST first, so its bans apply. Spec `core_plugin_appsec_bot-detection` drops "AppSec captcha envelope is parsed and relayed" for two new requirements; the header table in `core_plugin_middleware_bouncer` gains `ban:appsec-action-empty`. The mock AppSec stand-in returns the real captcha envelope on GET only, and a new mock e2e scenario solves it through the form POST.

## What this changes
**Operators.** An AppSec `SetRemediation("captcha")` now shows the router's configured captcha (configure a captcha provider on that router, or visitors get the ban page with `ban:captcha-downgrade`), and a bodyless custom AppSec action is a ban with `ban:appsec-action-empty`.
**Admin users.** None.
**Developers.** `handleCaptchaKindServeHTTP` takes the header reason and downgrade ban reason from its caller; on routers with AppSec and a usable captcha, a POST carrying `crowdsec_captcha_challenge=v1` that AppSec allows goes to the captcha gate instead of the backend.
**End users.** A visitor asked for a captcha by AppSec sees a captcha page they can solve, instead of a blank page.

## Merge readiness
In progress. 1 items remain.

Priority: P2 — real end-user pain (blank page instead of a captcha) limited to operators who use AppSec `captcha` or custom actions
Reviewed head: 6768fae6
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
| Branch | 2026-11-14-appsec-captcha-verdict pushed | `git` |
| OpenSpec | appsec-captcha-verdict | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/206 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/openspec/changes/appsec-captcha-verdict/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/openspec/changes/appsec-captcha-verdict/proposal.md) — modified


## Deviations from the ask
- taken: an AppSec `captcha` verdict is remediated as a captcha. → also route a POST carrying `crowdsec_captcha_challenge=v1` to the captcha gate when AppSec allowed it, so the form can be validated even when the operator's rule does not match the POST. — `pkg/bouncer/bouncer.go (serveAppSec), pkg/captcha/captcha.go (HasChallengeMarker)` — AppSec judges each request alone; without this, a rule that matches the GET but not the form POST forwards the solve to origin and the captcha can never be solved.. Requester: not asked.


## Follow-up issues
- [ ] [Lifecycle Pester e2e fails on ~20 s timeouts with unchanged product code](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/knowledge/debt/2026-11-14-lifecycle-e2e-flaky-timeouts.md) — the lifecycle Pester job failed twice and passed once on unchanged product code, on ~20 s timeouts in LAPI-only tests.


## How this fits together
Ticket 2026-11-14-appsec-captcha-verdict on branch 2026-11-14-appsec-captcha-verdict targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/206; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should an AppSec `captcha` verdict serve the router's configured captcha, or only the ban page (the review's minimal step)? | bounded asked — reverses requirement "AppSec captcha envelope is parsed and relayed" whose one caller (`applyAppsecServeHTTP`) and two locking tests were enumerated in `pkg/`; requirement.md Desired line 1 names remediating AppSec `captcha` as a captcha | assumed — serve the configured captcha through `handleCaptchaKindServeHTTP`; no usable captcha client → `ban:captcha-downgrade`. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_standards.md) — 5 total, 0 pending, 5 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_nitpicks.md) — 3 total, 0 pending, 3 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_security.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-captcha-verdict/devstate/staging/2026/11/2026-11-14-appsec-captcha-verdict/codereview_coverage.md) — 2 total, 0 pending, 2 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6768fae68cbce89fbda2a07ab6011eb86c81b801 | Card must match the branch you measured |

### Stored data model
None.
