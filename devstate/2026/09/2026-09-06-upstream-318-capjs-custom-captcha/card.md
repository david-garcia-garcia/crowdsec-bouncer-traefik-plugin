Developer review: ready for review — 2026-09-06T15:40:00Z

## What this changes
**Operators.** Set `captchaCustomValidateBody: json` (and `captchaCustomResponse: cap-token`) when `captchaProvider` is `custom` so CapJS Standalone `/siteverify` accepts the plugin's POST. Omit or `form` keeps today's urlencoded `secret`/`response`.

**Admin users.** None.

**Developers.** `pkg/captcha.Client.Validate` posts JSON `secret`/`response` when custom body is `json`; otherwise `PostForm`. Spec `core_plugin_captcha_custom-verify`.

**End users.** Solved CapJS challenges can pass verification when the operator sets the JSON knob.

## Motivation
On `master`, custom captcha verification always sends urlencoded `secret` and `response` via `PostForm`. CapJS Standalone expects JSON `POST` to `/siteverify` with the same keys. Without this change, CapJS users stay blocked on custom captcha despite existing custom-provider config knobs.

## Merge readiness
Ready for review. CI succeeded on head 1505da6.

Priority: P2 — real operator pain configuring CapJS custom captcha, with Wicketkeeper as workaround for urlencoded providers only.
Reviewed head: 1505da6
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | Main Process and both e2e jobs succeeded |
| Local tests proof | N/A | Remote PR; CI proof covers this |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-318-capjs-custom-captcha pushed | git / pr-host |
| OpenSpec | custom-captcha-verify-body (archived) | openspec/changes/archive/2026-09-06-custom-captcha-verify-body/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/52 | pr-host |
| CI | Main Process 34042749247 success; e2e 34042749166 success | pr-host CI |
| Local tests | passed | go test ./pkg/captcha ./pkg/configuration ./pkg/bouncer |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_captcha_custom-verify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/openspec/changes/archive/2026-09-06-custom-captcha-verify-body/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] Extra custom-captcha verify fields/headers — this change ships JSON vs form only.
- [ ] [note] [large] Wicketkeeper example documents urlencoded `secret`/`response`; official `/v0/siteverify` is JSON `token`/`nonce`/`response`.

## How this fits together
Local ticket upstream#318 → PR #52. Custom captcha can POST JSON siteverify for CapJS; default form keeps Wicketkeeper-style setups.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Extra verify fields/headers (ticket “more control”)? | assumed — out of scope this change; JSON vs form is enough for CapJS Standalone. | explore |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/devstate/2026/09/2026-09-06-upstream-318-capjs-custom-captcha/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/devstate/2026/09/2026-09-06-upstream-318-capjs-custom-captcha/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/devstate/2026/09/2026-09-06-upstream-318-capjs-custom-captcha/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/devstate/2026/09/2026-09-06-upstream-318-capjs-custom-captcha/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/devstate/2026/09/2026-09-06-upstream-318-capjs-custom-captcha/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 1505da688c6cf29666f5a33dcbf5be277817f09f | Card matches branch measured at pullrequest close |

### Stored data model
None.

### Technical review
Best possible solution: custom-only `form`/`json` enum defaulting to form so Wicketkeeper stays on `PostForm` and CapJS can opt into JSON `secret`/`response`.

Do we have a high-confidence way to reproduce? Yes — `pkg/captcha` httptest asserts JSON vs urlencoded bodies.

Is this the best way to solve the issue? Yes — matches Cap Standalone docs.

### Evidence
What I checked:
- Main Process 34042749247 success
- e2e 34042749166 success
- Five axis files none.

### Rank-up moves
None.
