Developer review: needs changes — 2026-09-06T17:04:31Z



IssueKey: 2026-09-06-captcha-handler-hardening

JobName: 2026-09-06-captcha-handler-hardening



## What this changes

**Operators.** When a captcha provider is configured, `captchaFilePath` must point to a loadable template at startup; grace-period cache write failures no longer redirect solved users into a solve loop.



**Admin users.** None.



**Developers.** `cache.Client.Set` returns `error`; captcha `Validate(r, remoteIP)` sends `remoteip` on siteverify, gates 302 on grace cache write, and re-renders captcha (200) on retryable provider errors; `pkg/captcha/captcha_test.go` covers verify, ServeHTTP, and New paths; test cache stub renamed `NewFailingSetClientForTest`.



**End users.** Captcha challenges retry gracefully on provider outages instead of bare HTTP 400; solved captchas stick only after the grace cache write succeeds.



## Motivation

On `master`, the captcha handler can 302 after a successful verify even when the grace cache write fails (solve loop), start with a nil template when no path is configured, omit `remoteip` on siteverify, return bare HTTP 400 on provider outages, and has no unit tests for these paths. Without this change, captcha remediation stays fragile under Redis errors and provider failures.



## Merge readiness

Codereview complete with hard findings fixed; devdocsimpact is next. 2 items remain.



Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.

Reviewed head: 828a053

Owner decision: None. See Decision needed.



## Review scores

| Measure | Result | What it means |

| --- | --- | --- |

| Overall readiness | 2/6 | Scoped packages pass; full `go test ./...` failed on pre-existing root logging tests |

| CI proof | 1/6 | Branch pushed; CI not seen on implement commits |

| Local tests proof | 2/6 | `go test ./...` failed (Windows bouncer_logging_test TempDir cleanup); scoped packages ok after codereview fixes |

| Review resolution | N/A | No PR review comments |



## Verification

| Check | Result | Evidence |

| --- | --- | --- |

| Branch | 2026-09-06-captcha-handler-hardening pushed | git |

| OpenSpec | captcha-handler-hardening | openspec/changes/captcha-handler-hardening/ |

| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub |

| CI | not seen | not measured this Set |

| Local tests | failed | handoff.yaml localTests |

| PR comments | no comments | devstate/comments.md absent |



## Specs

- [core_plugin_captcha_handler](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/captcha-handler-hardening/proposal.md) — added

- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/captcha-handler-hardening/proposal.md) — modified



## Follow-up issues

None.



## How this fits together

Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → PR #28 → implement landed cache/config/captcha commits → codereview fixed test stub naming and `renderCaptcha` comment → devdocsimpact next.



## Decision needed

| Question | Decision | By |

| --- | --- | --- |

| Should `cache.Client.Set` return error (API change) or captcha use a test-only wrapper? | assumed — change `Set` to return `error`; minimal surface, redis already has the error, other callers unchanged behavior when ignored. | explore |

| HTTP status on grace cache write failure — 503 vs 200 re-render? | assumed — re-render captcha 200 with Error log; less disruptive than 503; ticket allows either with operator signal. | explore |

| Backward compat for deployments with provider set but empty template path? | assumed — breaking change accepted per ticket; validation fails at startup with clear error. | explore |



## Before merge

- [ ] [P2] Run devdocsimpact phase

- [x] Five-axis codereview on implement diff

- [x] Apply codereview hard findings (test stub rename, renderCaptcha comment)



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

| Specs in this PR | 1 added / 1 modified | OpenSpec deltas under captcha-handler-hardening |

| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |

| Reviewed head | 828a0530 | Codereview head including hard-fix commit |



### Stored data model

- Changed: cache key `<remoteIP>_captcha` / grace value — string — sample `d` written only after successful `Set`; redirect blocked on write failure.



### Technical review

Best possible solution: Minimal shared `Set` error seam plus captcha UX fixes match explore decisions; codereview only tightened test seam naming and method comment.



Do we have a high-confidence way to reproduce? Yes — `pkg/captcha/captcha_test.go` with httptest siteverify stub and `NewFailingSetClientForTest`.



Is this the best way to solve the issue? Yes — observable cache write gates redirect; startup validation prevents nil template; retryable errors reuse captcha page UX.



### Evidence

What I checked:

- Five-axis review on `origin/master...HEAD` excluding devstate and `.cursor`

- `go test ./pkg/captcha ./pkg/cache ./pkg/configuration` passed after codereview fixes

- Hard findings applied: `NewFailingSetClientForTest`, `renderCaptcha` comment



### Rank-up moves

None.



[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]

