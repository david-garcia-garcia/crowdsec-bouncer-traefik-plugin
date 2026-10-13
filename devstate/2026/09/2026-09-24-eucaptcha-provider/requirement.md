# Requirement
IssueKey: 2026-09-24-eucaptcha-provider

## Problem
Operators cannot select EU CAPTCHA (https://eu-captcha.eu/) as a first-class captcha provider. Dest accepts `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`. Upstream proposed the same provider on the maxlerebourg tree at https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 (context; that diff is not applied here). The delivery card must name that upstream pull request by URL, not as a GitHub issue number on this repo.

## Current (code)
- Provider allowlist is empty, `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, `custom`. Token `eucaptcha` is rejected: `pkg/configuration/configuration.go` `validateCaptcha`.
- Built-in widget + siteverify pairing is hcaptcha, recaptcha, turnstile only. `eucaptcha` is not in the map: `pkg/captcha/captcha.go` `infoProviders` / `New`.
- Stock challenge page templates script URL, CSS class, `data-sitekey`, and `data-callback="captchaCallback"`. The score-key hidden field is `g-recaptcha-response`. There is no `eu-captcha-response` field in the file: `captcha.html`.
- Built-in verify POSTs siteverify `secret`+`response` (form, or custom JSON). Success is the JSON `success` bit only. No `train`. Endpoint is not `https://api.eu-captcha.eu/v1/verify`: `pkg/captcha/siteverify.go`.
- Gate cookie is minted when `Validate` returns `Pass`: `pkg/captcha/captcha.go` `ServeHTTP`; `pkg/captcha/gate.go` `mintGateValue` / `setGateCookie`.
- `Validate` already receives the chosen client address and does not call the verifier on an empty token: `pkg/captcha/captcha.go` `Validate`.
- Empty client address is not a rejection: siteverify omits `remoteip` and still POSTs: `pkg/captcha/siteverify.go` `postSiteverify`. Assessments omit `userIpAddress` the same way: `pkg/captcha/assessments.go` `Pass`.
- Request User-Agent is not forwarded. Verifier `Pass` takes only token and remoteIP: `pkg/captcha/verifier.go`.
- Startup `/verify-credentials` probe: not found.

## Desired
- Accept provider value `eucaptcha` beside `hcaptcha`, `recaptcha`, `turnstile`, and `custom`.
- Keep the stock challenge page. Pairing for this provider supplies the vendor widget (script URL, CSS class, `data-sitekey`, `data-callback`, hidden field `eu-captcha-response`).
- Server verify is not siteverify and not custom JSON. POST `https://api.eu-captcha.eu/v1/verify` with JSON `sitekey`, `secret`, `client_ip`, `client_token`, `client_user_agent`.
- Mint the gate cookie only when `success` is true and `train` is false or null. A `train` true body (vendor forces `success` true when credentials are wrong or protection is off) must not mint the cookie.
- Forward the client address `Validate` already receives, and the request User-Agent. An empty client address is a rejection.
- Do not submit empty tokens to the vendor.
- Do not add a startup `/verify-credentials` probe. The `train` check is the fail-closed path.
- Delivery card names https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 as that upstream pull request.

## Affected
- `pkg/configuration/configuration.go` — provider allowlist
- `pkg/captcha/captcha.go` — `New` widget/verifier pairing
- `pkg/captcha/verifier.go` — `Pass` surface (User-Agent / empty address)
- `pkg/captcha/siteverify.go` — not the eucaptcha verify owner
- `pkg/captcha/gate.go` — cookie mint stays on Pass
- `captcha.html` — keep
- `README.md` — provider list / `CaptchaProvider` expected values
- `openspec/specs/core_plugin_middleware_captcha-widget/spec.md` — pairing and stock page
- `openspec/specs/core_plugin_middleware_captcha-siteverify/spec.md` — siteverify is not this vendor
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` — provider token list

## Out of scope
- Cherry-pick or port of https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317
- That patch's cache client, `FormValue`, Content-Type substring, HTTP 400 handling, provider branch inside `Validate`, and startup credential log
- A startup `/verify-credentials` probe
- Changing the stock challenge page

## Unknowns
- Vendor widget script URL and CSS class (ticket says the stock page already matches; dest has no `eucaptcha` pairing to measure).
- Whether the vendor widget injects hidden field `eu-captcha-response` into the form (like hcaptcha injects `h-captcha-response`) so `captcha.html` needs no extra field.
- Exact JSON types, HTTP statuses, and error bodies for `/v1/verify` (named page https://docs.eu-captcha.eu/en/api/verify/ is unmeasured here).
- Whether an empty User-Agent is a rejection the same way as an empty client address.
- How `train` is encoded when absent vs explicit false vs null.
- Blast radius on live specs that freeze the current provider list (`config-validation`, `captcha-widget`, `captcha-siteverify`).

## Tensions
- Ticket lists `eucaptcha` beside hcaptcha, recaptcha, turnstile, and custom. Dest already has `recaptcha-enterprise`. The ticket does not ask to drop it.
- Ticket says the stock page already matches, including hidden field `eu-captcha-response`. `captcha.html` has no that name; the only hardcoded hidden field is `g-recaptcha-response` on the score branch.
- Live spec `openspec/specs/core_plugin_middleware_captcha-widget/spec.md` says `New` is the only provider switch and `Validate` must not name a provider. Upstream PR #317 branched inside `Validate`; that shape is out of scope as a port. Dest already forbids it.
