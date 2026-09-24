## Motivation
Operators who want EU CAPTCHA (https://eu-captcha.eu/) as the captcha challenge cannot select it. Captcha already allowlists `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`; each token pairs a widget with a verifier. Token `eucaptcha` is rejected at config validation, so that vendor is not a first-class choice. Upstream proposed the same provider on the maxlerebourg tree at https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 (context; that pull request is not an issue on this repo).

EU CAPTCHA is not a siteverify sibling. Built-in verify POSTs siteverify `secret`+`response` (or custom JSON in that shape) and reads only the `success` bit, or it calls reCAPTCHA Enterprise assessments. There is no pairing for `verify.js` / class `eu-captcha` / field `eu-captcha-response`, and no POST to `https://api.eu-captcha.eu/v1/verify` with JSON `sitekey`, `secret`, `client_ip`, `client_token`, and `client_user_agent`. The vendor also returns `train`: when credentials are wrong or protection is off, `success` is still true and `train` is true. A success-bit-only verifier would treat that as a pass and mint the gate cookie.

Leaving the gap means operators who need that EU-hosted challenge have no valid `CaptchaProvider` value, and a `custom` siteverify wiring cannot send the vendor JSON or refuse a `train` true body. Other providers stay usable; the miss is this one token.

Priority: P2 — operators who need EU CAPTCHA cannot select it, with blast radius limited to that missing choice

## Implementation
Construction adds a named `eucaptcha` case next to `recaptcha-enterprise`: the official widget (script `https://cdn.eu-captcha.eu/verify.js`, class `eu-captcha`, token field `eu-captcha-response`, retry after reject) and a dedicated verifier. That verifier POSTs JSON to `https://api.eu-captcha.eu/v1/verify` on the existing captcha HTTP client. `Validate` stays provider-blind and forwards the challenge request User-Agent into `Pass`. Empty client address is a local reject with no vendor POST on this verifier only; empty User-Agent is still sent. Pass-true only when HTTP 200 JSON has `success` true and `train` is false or null (`train` true is reject, so the gate cookie is not minted). Non-2xx or undecodable JSON is an error and the challenge is re-rendered. Config allowlist accepts `eucaptcha` without dropping `recaptcha-enterprise`; `CaptchaSecretKey` stays required. Stock `captcha.html` is unchanged. `Pass` takes a User-Agent argument; siteverify and assessments ignore it.

## What this changes
**Operators.** They can set `captchaProvider` to `eucaptcha` and must supply `captchaSiteKey` and `captchaSecretKey`; routers that do not select that token are unchanged.
**Admin users.** None.
**Developers.** `Verifier.Pass` is `Pass(token, remoteIP, userAgent string)` (siteverify and assessments ignore `userAgent`); `eucaptcha` is a construction pairing, not a siteverify entry, and Pass-true for it requires `success` true and `train` false or null.
**End users.** When the operator selects `eucaptcha`, challenged visitors complete the EU CAPTCHA widget instead of another vendor.

## Merge readiness
In progress. 1 items remain.

Priority: P2 — operators who need EU CAPTCHA cannot select it, with blast radius limited to that missing choice
Reviewed head: ad18f541
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-eucaptcha-provider pushed | `git` |
| OpenSpec | eucaptcha-provider | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/155 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_captcha-enterprise-config](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — modified
- [core_plugin_middleware_captcha-eucaptcha-verify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — added
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/openspec/changes/eucaptcha-provider/proposal.md) — modified


## Deviations from the ask
- taken: eucaptcha beside hcaptcha, recaptcha, turnstile, and custom. → those tokens plus dest's recaptcha-enterprise. — `pkg/configuration/configuration.go validateCaptcha` — dest already owns that token; dropping it would distort the allowlist this change extends.. Requester: not asked.


## Follow-up issues
- [ ] [Provider allowlist lives on captcha-enterprise-config](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/knowledge/debt/2026-09-24-allowlist-on-captcha-enterprise-config.md) — provider allowlist lives on leaf `captcha-enterprise-config`.


## How this fits together
Ticket 2026-09-24-eucaptcha-provider on branch 2026-09-24-eucaptcha-provider targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/155; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Is an empty User-Agent a rejection the same way as an empty client address? | additive asked — new verifier this change creates; Unknowns on requirement.md; Desired names empty address as rejection only | assumed — no. Forward r.UserAgent() including empty string. Do not local-reject empty UA. Official field is necessary but the owner does not state HTTP for empty or missing UA. Empty client address stays a local reject on this verifier. Source knowledge/research/ext_eucaptcha_verify/. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_security.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-eucaptcha-provider/devstate/2026/09/2026-09-24-eucaptcha-provider/codereview_coverage.md) — 2 total, 0 pending, 2 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 3 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | ad18f5413369ddf1c18add5dcec4daa4349e2869 | Card must match the branch you measured |

### Stored data model
None.
