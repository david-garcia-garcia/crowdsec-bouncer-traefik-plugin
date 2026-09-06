Developer review: in progress — 2026-09-06T15:02:00Z



IssueKey: 2026-09-06-captcha-handler-hardening

JobName: 2026-09-06-captcha-handler-hardening



## What this changes

**Operators.** None yet — propose only; runtime behavior unchanged until implement.



**Admin users.** None.



**Developers.** OpenSpec change `captcha-handler-hardening` adds spec deltas for captcha handler hardening and cache `Set` error return; implement follows `tasks.md`.



**End users.** None.



## Motivation

On `master`, the captcha handler can 302 after a successful verify even when the grace cache write fails (solve loop), start with a nil template when no path is configured, omit `remoteip` on siteverify, return bare HTTP 400 on provider outages, and has no unit tests for these paths. Without this change, captcha remediation stays fragile under Redis errors and provider failures.



## Merge readiness

Propose complete; implement is next. 5 items remain.



Priority: P2 — real end-user pain (captcha solve loops and broken 400 responses) with limited blast radius.

Reviewed head: 15720fe

Owner decision: None. See Decision needed.



## Review scores

| Measure | Result | What it means |

| --- | --- | --- |

| Overall readiness | 1/6 | Propose only; no product code delta yet |

| CI proof | 1/6 | Branch pushed; CI not seen on propose commit |

| Local tests proof | N/A | Before implement |

| Review resolution | N/A | No PR review comments |



## Verification

| Check | Result | Evidence |

| --- | --- | --- |

| Branch | 2026-09-06-captcha-handler-hardening pushed | git |

| OpenSpec | captcha-handler-hardening | openspec/changes/captcha-handler-hardening/ |

| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/28 | GitHub |

| CI | not seen | not measured this Set |

| Local tests | none | handoff.yaml localTests |

| PR comments | no comments | devstate/comments.md absent |



## Specs

- [core_plugin_captcha_handler](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/captcha-handler-hardening/proposal.md) — added

- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-captcha-handler-hardening/openspec/changes/captcha-handler-hardening/proposal.md) — modified



## Follow-up issues

None.



## How this fits together

Local bug-hunt ticket → branch `2026-09-06-captcha-handler-hardening` → stub PR #28 → explore → propose (OpenSpec `captcha-handler-hardening`) → implement next.



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

None.



## Agent review details



### Review metrics

| Metric | Value | Why it matters |

| --- | --- | --- |

| Specs in this PR | 1 added / 1 modified | OpenSpec deltas under captcha-handler-hardening |

| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No PR comments |

| Reviewed head | 15720fe | Propose commit on branch |



### Stored data model

None.



### Technical review

Best possible solution: OpenSpec proposal matches explore decisions — `Set` error return, 200 re-render on grace write failure, startup template validation, `remoteip` on siteverify, retryable-error UX, unit-test plan.



Do we have a high-confidence way to reproduce? No — unit tests planned in tasks, not written yet.



Is this the best way to solve the issue? Yes — minimal API surface with clear UX and validation paths versus `master`.



### Evidence

What I checked:

- `requirement.md` and `explore.md` decisions reflected in proposal, design, tasks, and spec deltas

- `openspec validate captcha-handler-hardening --strict` passed

- FindSpecHost verdicts recorded in `devstate/specs.md`



### Rank-up moves

None.



[sgsi-dev-ticket-status:2026-09-06-captcha-handler-hardening]

