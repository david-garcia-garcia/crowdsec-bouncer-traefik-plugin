Developer review: in progress — 2026-09-06T15:14:06Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `custom-captcha-verify-body` adds spec `core_plugin_captcha_custom-verify`; usage packet `knowledge/devdocs/core_plugin_captcha.md` and research `ext_capjs_siteverify/` land with it.

**End users.** None.

## Motivation
On `master`, custom captcha verification always sends urlencoded `secret` and `response` via `PostForm`. CapJS Standalone expects JSON `POST` to `/siteverify` with the same keys. Operators pointing `CaptchaCustomValidateURL` at CapJS cannot verify solved challenges without an external adapter proxy. Without this change, CapJS users stay blocked on custom captcha despite existing custom-provider config knobs.

## Merge readiness
Propose complete; implement not started. 5 items remain.

Priority: P2 — real operator pain configuring CapJS custom captcha, with Wicketkeeper as workaround for urlencoded providers only.
Reviewed head: b979f45
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress; apply not landed |
| CI proof | 3/6 | Main Process in progress; e2e queued |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-318-capjs-custom-captcha pushed | git / pr-host |
| OpenSpec | custom-captcha-verify-body | openspec/changes/custom-captcha-verify-body/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/52 | pr-host |
| CI | build 34041574737 queued; Main Process 34041574848 in progress | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_captcha_custom-verify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/openspec/changes/custom-captcha-verify-body/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] Extra custom-captcha verify fields/headers — this change ships JSON vs form only.
- [ ] [note] [large] Wicketkeeper example documents urlencoded `secret`/`response`; official `/v0/siteverify` is JSON `token`/`nonce`/`response`.

## How this fits together
Local ticket upstream#318 → branch `2026-09-06-upstream-318-capjs-custom-captcha` → stub PR #52. Propose is apply-ready; implement next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Extra verify fields/headers (ticket “more control”)? | assumed — out of scope this change; JSON vs form is enough for CapJS Standalone. | explore |

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
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b979f45b1829a9e132e55d5b7e2ef3a506bbc56a | Card matches branch measured at propose close |

### Stored data model
None.

### Technical review
Best possible solution: public `captchaCustomValidateBody` `form`/`json` (default form) applied only for custom provider.

Do we have a high-confidence way to reproduce? No product tests yet.

Is this the best way to solve the issue? Yes — matches explore.

### Evidence
What I checked:
- openspec status 4/4 for custom-captcha-verify-body
- FindSpecHost new core_plugin_captcha_custom-verify

### Rank-up moves
None.
