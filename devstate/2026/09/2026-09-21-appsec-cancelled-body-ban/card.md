## Progress

| Phase | Work | Card | Duration |
| --- | --- | --- | --- |
| Prepare | done | done | 1m |
| Explore | done | done | 2m |
| Propose | done | done | 11m |
| Implement | done | done | 8m |
| Code review | done | done | 4m |
| Devdocs impact | — | — | — |
| Archive | — | — | — |
| Pull request | — | — | — |

Last updated: 2026-09-21 16:55 UTC

## Motivation
With AppSec enabled, the bouncer buffers readable POST, PUT, PATCH, and DELETE bodies before calling the AppSec listener. That path matches normal forwardable requests: known or positive `Content-Length`, body not classified as unreadable under HTTP/2 or HTTP/3 streaming rules.

If the client stops sending the body mid-copy (HTTP/2 stream cancel, request context canceled, truncated body versus `Content-Length`), `io.ReadAll` on the tee/limit reader fails. `newAppsecBodyRequest` wraps that as `appsecQuery:GetBody` and does not consult `crowdsecAppsecFailureAction`. `applyAppsecServeHTTP` treats any non-captcha `Query` error as an AppSec failure and responds with HTTP 403 and `ReasonAPPSEC`, even though AppSec never received the request. Operators who set `crowdsecAppsecFailureAction: passthrough` still hit this ban path; the failure is easy to miss at default log level because the message looks like a generic AppSec query error.

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

Leaving it in place produces false AppSec bans on benign client disconnects, undermines the unified failure-action knob for a common edge case, and can block or confuse end users who already abandoned the request.

Priority: P2 — real operator and end-user pain on client disconnect, with `FailureAction` intended as the control but ineffective on this path today.

## Implementation
After `io.ReadAll` fails while buffering a forwardable body, read errors classified as client-gone (`context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` via `errors.Is`) become `errClientBodyDropped`. `Query` maps that sentinel through the existing `resultForFailureAction` helper with message prefix `appsecQuery:clientBodyDropped`, the same family as unreachable, AppSec 500, and AppSec response-body I/O fallbacks. Unclassified read faults keep `appsecQuery:GetBody` wrapping so they still follow today’s ban wiring in `applyAppsecServeHTTP`.

`passthrough` returns allow without reaching AppSec. `ban` and `captcha` use the existing failure-action mapping without calling AppSec. No bouncer or new config key changes; regression coverage lives in `pkg/appsec/zzz_query_test.go` (table over the three client-gone errors plus an unclassified error that must stay on the `GetBody` path).

## What this changes
**Operators.** `crowdsecAppsecFailureAction` now governs client disconnect or cancel during AppSec body buffering; `passthrough` stops issuing false `ReasonAPPSEC` 403s on that path, and logs/errors distinguish `appsecQuery:clientBodyDropped` from unclassified `appsecQuery:GetBody` faults.
**Admin users.** None.
**Developers.** AppSec `Query` honors failure action for classified client-body-dropped reads; unclassified body read errors remain `appsecQuery:GetBody` and still surface as ban-path errors from `Query`.
**End users.** Mid-upload disconnect with operator `passthrough` no longer receives a false AppSec 403; with `ban`, the request is still forbidden but via the failure-action drop path rather than a spurious AppSec verdict.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator and end-user pain on client disconnect, with `FailureAction` intended as the control but ineffective on this path today.
Reviewed head: 233a1508
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
| Branch | 2026-09-21-appsec-cancelled-body-ban pushed | `git` |
| OpenSpec | 2026-09-21-appsec-cancelled-body-ban | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/133 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/openspec/changes/2026-09-21-appsec-cancelled-body-ban/proposal.md) — modified
- 2026-09-21-appsec-cancelled-body-ban — added

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395 on branch 2026-09-21-appsec-cancelled-body-ban targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/133; CI not seen.

## Explore Decisions
None.

## Before merge
None.

## Findings
[P3] OpenSpec task 3.2 (update `knowledge/devdocs/core_plugin_appsec.md` for client-body-dropped versus unreadable versus unclassified `GetBody`) remains unchecked in the change tasks; expect devdocsimpact before merge if that slice is required for this fork.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_standards.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_nitpicks.md) — 4 total, 0 pending, 4 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_spec.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_scope.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/devstate/2026/09/2026-09-21-appsec-cancelled-body-ban/codereview_coverage.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 233a1508d67899d0c2e267ecc414c000bcaa905b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 233a1508d67899d0c2e267ecc414c000bcaa905b)

### Rank-up moves
None.
