## Motivation
Traefik middleware `New` for the CrowdSec bouncer plugin used to fail when a captcha provider was configured but the captcha HTML file was missing or empty, so the route never came up even though ban remediation could still run with an empty body. An empty ban template path was accepted with no startup signal, so operators could deploy without a ban page and only discover it from silent 403 responses.

That mismatch blocked bouncing routers on template filesystem mistakes and hid ban-page gaps until traffic hit remediation.

Priority: P2 — real operator pain (dead route or silent empty ban) with a workaround (fix template paths before deploy).

## Implementation
Validation no longer fail-closes on captcha or ban template load in `ValidateParams`; site, secret, and gate checks stay when captcha is enabled. Each owner warns once at construction: the captcha client logs `crowdsec captcha template unavailable`, leaves `Valid` false, and returns success so existing remediation code bans captcha decisions; the bouncer logs `crowdsec bouncer ban template unavailable` and keeps a nil ban template so GET ban stays status-only. Bounce-only routers never open captcha, so unused default `/captcha.html` is not read or warned.

## What this changes
**Operators.** Watch for one-time startup WARN lines when captcha or ban template paths are empty or unreadable; the middleware still starts and captcha remediations fall back to ban with an empty body.

**Admin users.** None.

**Developers.** `ValidateParams` and `Client.New` no longer error on missing captcha templates; `Client.New` succeeds with `Valid` false instead of returning `GetTemplate` errors. Ban template load errors are warned in `bouncer.New`, not validation.

**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain (dead route or silent empty ban) with a workaround (fix template paths before deploy).
Reviewed head: ea195d65
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
| Local tests | passed | handoff.yaml localTests |
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
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_dead.md) — 1 total, 0 pending, 1 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-template-startup-warn/devstate/2026/09/2026-09-24-template-startup-warn/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | ea195d6527fde982671130374b24c2c1e71bc2f7 | Card must match the branch you measured |

### Stored data model
None.
