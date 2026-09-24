## Motivation
This ticket’s job is to close a proof gap against https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397: the two edges that report named as failures in the other plugin were already this tree’s AppSec challenge protocol, and nothing here proved them.

#397 describes `action=challenge`, `http_status=200`, and empty or missing `user_body_content` coming back as HTTP 200 with an empty body, and a writer that already has `Content-Security-Policy` receiving a second CSP because `user_headers` were appended. The protocol is fail-closed to the configured ban response (status must not be committed before the empty-body check), same-name AppSec headers replace, and each `user_cookies` value stays its own `Set-Cookie`.

What was missing is proof of those two edges. The existing empty-challenge case used a nil ban template and only checked HTTP 403 plus the ban header, so it never showed the operator ban page and never sent an explicit empty-string `user_body_content`. The existing structured-challenge relay asserted one cookie via `Header().Get` and never pre-set CSP on the writer, so replace-versus-append and two separate `Set-Cookie` values were unobserved. The live challenge spec already named empty-challenge ban; it did not name CSP replace or separate cookies. Left alone, the two #397 edges stay an unproven claim.

Priority: P3 — a proof and spec gap with no current user or operator harm

## Implementation
The proof sits on the existing AppSec envelope test seam: the same `testBouncerWithAppsec` fixture and `handleNextServeHTTP` path as the other structured-challenge cases. One case table-drives omitted `user_body_content` (`{"action":"challenge","http_status":200}`) and explicit `user_body_content:""`, with a non-nil ban template, and asserts HTTP 403, `X-Remediation: ban`, and the rendered operator ban page for `192.0.2.10` — not HTTP 200 with an empty body. The other pre-sets `Content-Security-Policy: default-src 'self'` on the recorder, then AppSec returns `script-src 'none'` plus two `user_cookies`; it asserts `Header().Values` has exactly one CSP equal to the AppSec value and two separate `Set-Cookie` strings. Production was left unchanged. The live challenge spec gained the two header and cookie scenarios; empty-challenge ban was already named there.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Keep the two #397 challenge invariants: empty or missing `user_body_content` is the operator ban page, same-name `user_headers` replace (one CSP), and each `user_cookies` value is its own `Set-Cookie`.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — a proof and spec gap with no current user or operator harm
Reviewed head: 759802b9
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/d7d09002e646e9820b78574f978c0deaa7576a53/checks |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-appsec-challenge-coverage pushed | `git` |
| OpenSpec | appsec-challenge-coverage | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/146 | pr-host |
| CI | build d7d09002e646e9820b78574f978c0deaa7576a53 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/d7d09002e646e9820b78574f978c0deaa7576a53/checks | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/d7d09002e646e9820b78574f978c0deaa7576a53/checks |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/openspec/changes/archive/2026-09-24-appsec-challenge-coverage/proposal.md) — modified

Completed:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-appsec-challenge-coverage on branch 2026-09-24-appsec-challenge-coverage targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/146; CI build d7d09002e646e9820b78574f978c0deaa7576a53 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/d7d09002e646e9820b78574f978c0deaa7576a53/checks.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Is TestHandleNextServeHTTPEmptyChallengeBodyBans enough for empty challenge coverage? | additive asked — new assertions on the existing AppSec test file; Desired names operator ban page and missing or empty | assumed — no; add missing and empty-string user_body_content cases with a non-nil banTemplate so the operator ban page is asserted | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-appsec-challenge-coverage/devstate/2026/09/2026-09-24-appsec-challenge-coverage/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 759802b970ff4ec80c7b2e31e118801d10639f81 | Card must match the branch you measured |

### Stored data model
None.
