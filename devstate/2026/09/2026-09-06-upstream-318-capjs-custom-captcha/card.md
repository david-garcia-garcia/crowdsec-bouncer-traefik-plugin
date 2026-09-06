Developer review: in progress — 2026-09-06T15:11:06Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research packet `knowledge/research/ext_capjs_siteverify/` records Cap Standalone siteverify as JSON POST `secret`/`response` (not urlencoded).

**End users.** None.

## Motivation
On `master`, custom captcha verification always sends urlencoded `secret` and `response` via `PostForm`. CapJS Standalone expects JSON `POST` to `/siteverify` with the same keys. Operators pointing `CaptchaCustomValidateURL` at CapJS cannot verify solved challenges without an external adapter proxy, while Wicketkeeper works with today's form path. Without this change, CapJS users stay blocked on custom captcha despite existing custom-provider config knobs.

## Merge readiness
Explore complete; propose not started. 6 items remain.

Priority: P2 — real operator pain configuring CapJS custom captcha, with Wicketkeeper as workaround for urlencoded providers only.
Reviewed head: 7554a9c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still queued; no product apply yet |
| CI proof | 3/6 | Checks queued on head 7554a9c |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-318-capjs-custom-captcha pushed | git / pr-host |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/52 | pr-host |
| CI | build 34041483345 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041483345 ; Main Process 34041483351 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041483351 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] Extra custom-captcha verify fields/headers — this change ships JSON vs form only. CapJS needs only `secret` and `response`.
- [ ] [note] [large] Wicketkeeper example documents urlencoded `secret`/`response`; official `/v0/siteverify` is JSON `token`/`nonce`/`response`. Not retargeted here.

## How this fits together
Local ticket upstream#318 → branch `2026-09-06-upstream-318-capjs-custom-captcha` → stub PR #52. Explore decided `CaptchaCustomValidateBody` `form`/`json` (default form) for custom provider only; propose next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Extra verify fields/headers (ticket “more control”)? | assumed — out of scope this change; JSON vs form is enough for CapJS Standalone. Follow-up if another provider needs more. | explore |

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
| Specs in this PR | none | No OpenSpec change yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 7554a9ca3fd3b21dfc9a25348591889c430e49e0 | Card matches branch measured at explore close |

### Stored data model
None.

### Technical review
Best possible solution: explicit `form`/`json` enum on a new custom-only knob, default empty=`form`, so Wicketkeeper and built-in providers stay on `PostForm` and CapJS can opt into JSON `secret`/`response`.

Do we have a high-confidence way to reproduce? No — no `pkg/captcha` tests yet; CapJS contract is sourced from official docs and `tiagozip/cap` siteverify handler.

Is this the best way to solve the issue? Yes — MIME strings invite typos; URL auto-detect is wrong; extra fields are not required for CapJS.

### Evidence
What I checked:
- `pkg/captcha/captcha.go` Validate uses PostForm only
- `pkg/configuration/configuration.go` custom captcha fields; no body-format knob
- CapJS Standalone siteverify JSON POST (trycap.dev/guide/standalone/; knowledge/research/ext_capjs_siteverify/)
- Widget token field `cap-token` maps via existing `CaptchaCustomResponse`

### Rank-up moves
None.
