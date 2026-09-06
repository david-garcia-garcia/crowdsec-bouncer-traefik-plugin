Developer review: in progress — 2026-09-06T15:19:41Z

## What this changes
**Operators.** Set `captchaCustomValidateBody: json` (and `captchaCustomResponse: cap-token`) when `captchaProvider` is `custom` so CapJS Standalone `/siteverify` accepts the plugin's POST. Omit or `form` keeps today's urlencoded `secret`/`response`.

**Admin users.** None.

**Developers.** `pkg/captcha.Client.Validate` posts JSON `secret`/`response` when custom body is `json`; otherwise `PostForm`. Spec `core_plugin_captcha_custom-verify`.

**End users.** Solved CapJS challenges can pass verification when the operator sets the JSON knob.

## Motivation
On `master`, custom captcha verification always sends urlencoded `secret` and `response` via `PostForm`. CapJS Standalone expects JSON `POST` to `/siteverify` with the same keys. Without this change, CapJS users stay blocked on custom captcha despite existing custom-provider config knobs.

## Merge readiness
Implement landed; CI still queued. 4 items remain.

Priority: P2 — real operator pain configuring CapJS custom captcha, with Wicketkeeper as workaround for urlencoded providers only.
Reviewed head: 147e8bf
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Product apply landed; CI queued |
| CI proof | 3/6 | Main Process queued on 147e8bf |
| Local tests proof | N/A | Remote PR; CI proof covers this |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-318-capjs-custom-captcha pushed | git / pr-host |
| OpenSpec | custom-captcha-verify-body | openspec/changes/custom-captcha-verify-body/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/52 | pr-host |
| CI | Main Process 34041944785 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041944785 | pr-host CI |
| Local tests | passed | go test ./pkg/captcha ./pkg/configuration ./pkg/bouncer |
| PR comments | no comments | devstate/comments.md absent |

## Specs
- [core_plugin_captcha_custom-verify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-318-capjs-custom-captcha/openspec/changes/custom-captcha-verify-body/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] Extra custom-captcha verify fields/headers — this change ships JSON vs form only.
- [ ] [note] [large] Wicketkeeper example documents urlencoded `secret`/`response`; official `/v0/siteverify` is JSON `token`/`nonce`/`response`.

## How this fits together
Local ticket upstream#318 → branch `2026-09-06-upstream-318-capjs-custom-captcha` → PR #52. Implement added `captchaCustomValidateBody`; code review next.

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
| Reviewed head | 147e8bf266dee73b62719cecc4f9696f85505d60 | Card matches branch measured at implement close |

### Stored data model
None.

### Technical review
Best possible solution: custom-only `form`/`json` enum defaulting to form so Wicketkeeper stays on `PostForm` and CapJS can opt into JSON `secret`/`response`.

Do we have a high-confidence way to reproduce? Yes — `pkg/captcha` httptest asserts JSON vs urlencoded bodies.

Is this the best way to solve the issue? Yes — matches explore and Cap Standalone docs.

### Evidence
What I checked:
- `go test ./pkg/captcha/ ./pkg/configuration/ ./pkg/bouncer/` passed
- `pkg/captcha/captcha.go` `postSiteverify` JSON vs PostForm

### Rank-up moves
None.
