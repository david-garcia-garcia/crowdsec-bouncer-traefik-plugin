## Motivation
Captcha challenge HTML is the 200 this plugin writes on the original URL: Content-Type from the template, optional remediation header, then the template. That path does not Set-Cookie; the gate cookie is only on Pass before the 302. Ban HTML is the same pattern from the ban writer: Content-Type, optional remediation header, then the remediation status. AppSec challenge relay already copies engine `user_headers`, including `Cache-Control` when the engine sends it.

A CDN in front of Traefik stored that captcha HTML — HTTP 200 on the original URL, Content-Type only, no Set-Cookie. After the captcha decision was cleared, the CDN kept serving the stored page. Both writers omit `Cache-Control`. Ban HTML is the same cacheable remediation body with no cache header.

Left alone, clearing a captcha decision does not clear the cached HTML. Visitors keep solving a challenge CrowdSec has already dropped. Ban pages can stay stored the same way. CDN cache keys and TTLs are not in this tree; the plugin sent nothing a cache is required to treat as unstoreable.

Priority: P2 — real end-user pain, with a workaround or limited blast radius

## Implementation
On each writer this plugin owns, set `Cache-Control: no-cache, no-store` before WriteHeader. Challenge HTML gets it on the 200 path. The Pass 302 and the second-tab `WriteSolvedRedirect` set the same value, so a proxy cannot store a redirect to the same URL. The ban writer sets it once, so HEAD and nil-template bans carry it the same way Content-Type already does. The string is exactly that value — HAProxy SPOA captcha/ban returns and the AppSec challenge protocol example, no extra directives. AppSec envelope relay stays unchanged. Challenge 200, both solve 302s, and ban header tests assert the header.

## What this changes
**Operators.** No new plugin or Traefik key; after deploy, captcha challenge 200s, both solve redirects, and ban remediations send `Cache-Control: no-cache, no-store`.
**Admin users.** None.
**Developers.** Challenge HTML at 200, the Pass 302, `WriteSolvedRedirect`, and ban responses must set `Cache-Control: no-cache, no-store` before WriteHeader.
**End users.** A cache in front of Traefik that honors Cache-Control should stop serving a stored captcha page or a stored solve redirect after the decision is cleared; ban HTML should not stay stored either.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real end-user pain, with a workaround or limited blast radius
Reviewed head: 651cd097
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-25-remediation-cache-control pushed | `git` |
| OpenSpec | remediation-cache-control | `openspec/` |
| Pull request | none | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/openspec/changes/archive/2026-09-25-remediation-cache-control/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/openspec/changes/archive/2026-09-25-remediation-cache-control/proposal.md) — modified

Completed:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/openspec/specs/core_plugin_middleware_captcha-widget/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-25-remediation-cache-control on branch 2026-09-25-remediation-cache-control targeting master; PR no PR yet; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Must existing header tests gain Cache-Control assertions, or is a new neighbor test the right place? | additive asked — Affected names pkg/captcha/zzz_servehttp_test.go and pkg/bouncer/zzz_bouncer_test.go | assumed — extend those existing header tests (challenge 200 body case and TestHandleBanServeHTTPContentType / method table); do not add a new zzz_ file | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-remediation-cache-control/devstate/2026/09/2026-09-25-remediation-cache-control/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 651cd097268a10563c7d36265ca021645e3fb229 | Card must match the branch you measured |

### Stored data model
None.
