Developer review: needs changes — 2026-09-06T15:18:09Z

IssueKey: 2026-09-06-captcha-handler-hardening
JobName: 2026-09-06-captcha-handler-hardening

## What this changes
**Operators.** When a captcha provider is configured, `captchaFilePath` must point to a loadable template at startup; grace-period cache write failures no longer redirect solved users into a solve loop.

**Admin users.** None.

**Developers.** `cache.Client.Set` returns `error`; captcha `Validate(r, remoteIP)` sends `remoteip` on siteverify, gates 302 on grace cache write, and re-renders captcha (200) on retryable provider errors; `pkg/captcha/captcha_test.go` covers verify, ServeHTTP, and New paths; baseline specs synced for `core_plugin_captcha_handler` and `core_cache_client_isolated-store`.

**End users.** Captcha challenges retry gracefully on provider outages instead of bare HTTP 400; solved captchas stick only after the grace cache write succeeds.

## Motivation
On `master`, the captcha handler can 302 after a successful verify even when the grace cache write fails (solve loop), start with a nil template when no path is configured, omit `remoteip` on siteverify, return bare HTTP 400 on provider outages, and has no unit tests for these paths. Without this change, captcha remediation stays fragile under Redis errors and provider failures.

## Merge readiness
Pullrequest phase complete; Main Process CI failed on head `6ee817b`. 1 item remains.

Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.
Reviewed head: 6ee817b
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | Main Process CI failed; scoped local tests green |
| CI proof | 2/6 | Main Process failure; both e2e jobs succeeded |
| Local tests proof | 6/6 | Scoped packages passed; full `go test ./...` fails only on pre-existing Windows root `bouncer_logging_test` TempDir cleanup |
| Review resolution | 6/6 | No PR review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-captcha-handler-hardening pushed | git |
| OpenSpec | captcha-handler-hardening archived | openspec/changes/archive/2026-09-06-captcha-handler-hardening/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub |
| CI | Main Process failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041381920/job/101508655945 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041381948/job/101508657366 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041381948/job/101508657430 | GitHub check runs |
| Local tests | passed (scoped) | `go test ./pkg/captcha/... ./pkg/cache/... ./pkg/configuration/... ./pkg/bouncer/...` |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_captcha_handler](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/archive/2026-09-06-captcha-handler-hardening/proposal.md) — added
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/archive/2026-09-06-captcha-handler-hardening/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → PR #28 (title updated to ready gitmoji) → implement/cache/config/captcha hardening → codereview → devdocsimpact → archive → pullrequest synced with master, scoped tests green, CI mixed (Main Process red, e2e green).

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should `cache.Client.Set` return error (API change) or captcha use a test-only wrapper? | assumed — change `Set` to return `error`; minimal surface, redis already has the error, other callers unchanged behavior when ignored. | explore |
| HTTP status on grace cache write failure — 503 vs 200 re-render? | assumed — re-render captcha 200 with Error log; less disruptive than 503; ticket allows either with operator signal. | explore |
| Backward compat for deployments with provider set but empty template path? | assumed — breaking change accepted per ticket; validation fails at startup with clear error. | explore |

## Before merge
- [ ] [P2] Investigate and fix Main Process CI failure on head `6ee817b` (lint/test/yaegi on ubuntu)
- [x] Sync branch with origin/master
- [x] Update PR title to ready gitmoji (drop WIP)
- [x] Wait for CI on PR #28
- [x] Run scoped local tests

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/devstate/2026/09/2026-09-06-captcha-handler-hardening/codereview_standards.md) — 3 total, 0 pending, 2 completed, 1 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/devstate/2026/09/2026-09-06-captcha-handler-hardening/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/devstate/2026/09/2026-09-06-captcha-handler-hardening/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/devstate/2026/09/2026-09-06-captcha-handler-hardening/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/devstate/2026/09/2026-09-06-captcha-handler-hardening/codereview_dead.md) — 1 total, 0 pending, 1 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 1 modified | Synced to openspec/specs/ from archive deltas |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |
| Reviewed head | 6ee817b2d68ed3558bb48c461f949bdd75b6dec0 | Matches branch tip measured this phase |

### Stored data model
- Changed: cache key `<remoteIP>_captcha` / grace value — string — sample `d` written only after successful `Set`; redirect blocked on write failure.

### Technical review
Best possible solution: FindSpecHost verdicts applied — new captcha handler leaf, cache Set error folded into isolated-store spec; map regenerated with `captcha` component family.

Do we have a high-confidence way to reproduce? Yes — `pkg/captcha/captcha_test.go` with httptest siteverify stub and `NewFailingSetClientForTest`.

Is this the best way to solve the issue? Yes — baseline specs now match implemented behavior; change folder archived.

### Evidence
What I checked:
- Branch synced with origin/master (already up to date)
- PR #28 title updated to `🐛 fix(captcha): harden handler against cache failures and provider errors`
- CI check runs polled to completion (Main Process failure; e2e jobs success)
- Scoped local tests passed on Windows; full `go test ./...` fails only on pre-existing root `bouncer_logging_test` TempDir cleanup (file lock)

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]
