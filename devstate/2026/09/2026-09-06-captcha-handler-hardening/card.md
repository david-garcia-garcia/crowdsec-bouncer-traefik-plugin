Developer review: ready for review — 2026-09-06T15:37:57Z

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
Ready for human review. 0 items remain.

Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.
Reviewed head: e4ac4bb
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI green, scoped local tests passed, no open review items |
| CI proof | 6/6 | Main Process and both e2e jobs succeeded on head e4ac4bb |
| Local tests proof | 6/6 | Scoped packages passed; full `go test ./...` fails only on pre-existing Windows root `bouncer_logging_test` TempDir cleanup |
| Review resolution | 6/6 | No PR review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-captcha-handler-hardening pushed | git |
| OpenSpec | captcha-handler-hardening archived | openspec/changes/archive/2026-09-06-captcha-handler-hardening/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042506693/job/101511692237 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042506725/job/101511692517 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042506725/job/101511692742 | GitHub check runs |
| Local tests | passed (scoped) | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_captcha_handler](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/archive/2026-09-06-captcha-handler-hardening/proposal.md) — added
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/archive/2026-09-06-captcha-handler-hardening/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → PR #28 → captcha/cache/config hardening → codereview → devdocsimpact → archive → CI green on e4ac4bb → ready for review.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should `cache.Client.Set` return error (API change) or captcha use a test-only wrapper? | assumed — change `Set` to return `error`; minimal surface, redis already has the error, other callers unchanged behavior when ignored. | explore |
| HTTP status on grace cache write failure — 503 vs 200 re-render? | assumed — re-render captcha 200 with Error log; less disruptive than 503; ticket allows either with operator signal. | explore |
| Backward compat for deployments with provider set but empty template path? | assumed — breaking change accepted per ticket; validation fails at startup with clear error. | explore |

## Before merge
None.

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
| Reviewed head | e4ac4bbc5be88265a557a71fcc6176479e329fcb | Matches branch tip measured this phase |

### Stored data model
- Changed: cache key `<remoteIP>_captcha` / grace value — string — sample `d` written only after successful `Set`; redirect blocked on write failure.

### Technical review
Best possible solution: FindSpecHost verdicts applied — new captcha handler leaf, cache Set error folded into isolated-store spec; map regenerated with `captcha` component family.

Do we have a high-confidence way to reproduce? Yes — `pkg/captcha/captcha_test.go` with httptest siteverify stub and `NewFailingSetClientForTest`.

Is this the best way to solve the issue? Yes — baseline specs now match implemented behavior; change folder archived.

### Evidence
What I checked:
- CI check runs on head e4ac4bb — Main Process and both e2e jobs succeeded
- Scoped local tests passed per handoff.yaml
- PR #28 open with no review comments

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]
