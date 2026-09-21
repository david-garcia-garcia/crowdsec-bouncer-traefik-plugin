## Progress

| Phase | Work | Card | Duration |
| --- | --- | --- | --- |
| Prepare | done | done | 1m |
| Explore | done | done | 2m |
| Propose | done | done | 11m |
| Implement | done | done | 30m |
| Code review | done | done | — |
| Devdocs impact | done | done | 1m |
| Archive | done | done | 2m |
| Pull request | — | — | — |

Last updated: 2026-09-21 17:13 UTC

## Motivation
With AppSec enabled, the bouncer buffers readable POST, PUT, PATCH, and DELETE bodies before calling the AppSec listener. That path matches normal forwardable requests: known or positive `Content-Length`, body not classified as unreadable under HTTP/2 or HTTP/3 streaming rules.

If the client stops sending the body mid-copy (HTTP/2 stream cancel, request context canceled, truncated body versus `Content-Length`), `io.ReadAll` on the tee/limit reader fails. Previously the plugin treated that as an AppSec query failure and answered HTTP 403 with `ReasonAPPSEC`, even though AppSec never received the request. Operators who set `crowdsecAppsecFailureAction: passthrough` still hit that ban path.

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

Leaving it in place produces false AppSec bans on benign client disconnects, undermines the unified failure-action knob for a common edge case, and can block or confuse end users who already abandoned the request.

Priority: P2 — real operator and end-user pain on client disconnect, with `FailureAction` intended as the control but ineffective on this path today.

## Implementation
After `io.ReadAll` fails while buffering a forwardable body, read errors classified as client-gone (`context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` via `errors.Is`) become `ErrClientDisconnected`. `Query` returns that sentinel without calling AppSec and without `crowdsecAppsecFailureAction`. The bouncer logs TRACE (`client disconnected while buffering AppSec body`), sets `remediationHeadersCustomName` to `error:client-disconnected` when that header is configured, does not `WriteHeader`, does not increment LAPI dropped metrics, and does not call origin. Unclassified read faults keep `appsecQuery:GetBody` wrapping so they still follow today’s ban wiring in `applyAppsecServeHTTP`. Regression coverage lives in `pkg/appsec/zzz_query_test.go` and `pkg/bouncer/zzz_bouncer_test.go` (cites #395).

## What this changes
**Operators.** A client that disconnects mid-body is no longer logged as a CrowdSec 403/AppSec ban. If `remediationHeadersCustomName` is set, Traefik access logs can record `error:client-disconnected` (include that header in Traefik access-log fields). Plugin log is TRACE only.
**Admin users.** None.
**Developers.** `Query` returns `ErrClientDisconnected` for classified client-gone body reads; unclassified body read errors remain `appsecQuery:GetBody`.
**End users.** Mid-upload disconnect is not answered with a false AppSec 403.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator and end-user pain on client disconnect, with `FailureAction` intended as the control but ineffective on this path today.
Reviewed head: e590414a
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
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-appsec-cancelled-body-ban/openspec/changes/archive/2026-09-21-appsec-cancelled-body-ban/proposal.md) — modified
- core_plugin_appsec_client — modified
- core_plugin_middleware_bouncer — modified
- 2026-09-21-appsec-cancelled-body-ban — added

## Deviations from the ask
- taken: do not treat client-side body cancel as an AppSec ban; distinguish cancel from genuine faults; reporter offered pass-through or a fail-open option. → detect client-gone, TRACE-only log, optional `remediationHeadersCustomName` `error:client-disconnected`, do not call AppSec, origin, or `handleBanServeHTTP`. `crowdsecAppsecFailureAction` does not apply. — `pkg/bouncer/bouncer.go handleClientDisconnectedServeHTTP` — a cancelled stream has no client to protect or to serve 403 to; FailureAction would still 403 (default ban) or call origin (passthrough). Access-log header is the metric.. Requester: confirmed.

## Follow-up issues
None.

## How this fits together
Ticket https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395 on branch 2026-09-21-appsec-cancelled-body-ban targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/133; CI not seen.

## Explore Decisions
None.

## Before merge
None.

## Findings
None.

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
| Specs in this PR | 1 added / 3 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e590414a85cea45961339c8cd9ad4fe650fc37be | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, e590414a85cea45961339c8cd9ad4fe650fc37be)

### Rank-up moves
None.
