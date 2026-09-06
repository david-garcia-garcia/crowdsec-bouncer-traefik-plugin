Developer review: in progress — 2026-09-06T15:08:05Z

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
Archive complete; pullrequest phase is next. 1 item remains.

Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.
Reviewed head: b1b1d3f
Owner decision: None. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Archive landed; CI still not seen on branch |
| CI proof | 1/6 | Branch pushed; CI not seen |
| Local tests proof | 2/6 | `go test ./...` failed (Windows bouncer_logging_test TempDir cleanup); scoped packages ok |
| Review resolution | N/A | No PR review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-captcha-handler-hardening pushed | git |
| OpenSpec | captcha-handler-hardening archived | openspec/changes/archive/2026-09-06-captcha-handler-hardening/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub |
| CI | not seen | GitHub MCP get_status total_count 0 |
| Local tests | failed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_captcha_handler](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/archive/2026-09-06-captcha-handler-hardening/proposal.md) — added
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/archive/2026-09-06-captcha-handler-hardening/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → PR #28 → implement landed cache/config/captcha → codereview fixes → devdocsimpact → archive synced deltas to `openspec/specs/` and moved change to archive.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should `cache.Client.Set` return error (API change) or captcha use a test-only wrapper? | assumed — change `Set` to return `error`; minimal surface, redis already has the error, other callers unchanged behavior when ignored. | explore |
| HTTP status on grace cache write failure — 503 vs 200 re-render? | assumed — re-render captcha 200 with Error log; less disruptive than 503; ticket allows either with operator signal. | explore |
| Backward compat for deployments with provider set but empty template path? | assumed — breaking change accepted per ticket; validation fails at startup with clear error. | explore |

## Before merge
- [ ] [P2] Run pullrequest phase and wait for CI
- [x] Run archive phase
- [x] Run devdocsimpact phase
- [x] Five-axis codereview on implement diff

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
| Reviewed head | b1b1d3fe42f59692dbda618121b905ee8325dc18 | Pre-archive commit; archive sync pending push |

### Stored data model
- Changed: cache key `<remoteIP>_captcha` / grace value — string — sample `d` written only after successful `Set`; redirect blocked on write failure.

### Technical review
Best possible solution: FindSpecHost verdicts applied — new captcha handler leaf, cache Set error folded into isolated-store spec; map regenerated with `captcha` component family.

Do we have a high-confidence way to reproduce? Yes — `pkg/captcha/captcha_test.go` with httptest siteverify stub and `NewFailingSetClientForTest`.

Is this the best way to solve the issue? Yes — baseline specs now match implemented behavior; change folder archived.

### Evidence
What I checked:
- FindSpecHost verdicts on devstate/specs.md (core_plugin_captcha_handler new, core_cache_client_isolated-store fold)
- validate-spec-map.mjs --write + validate + validate-artifact-names.mjs all exit 0
- openspec status --change captcha-handler-hardening isComplete true; all tasks [x]

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]
