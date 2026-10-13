## Context

See proposal.md — Why. Today `validateCaptcha` allowlists empty / `hcaptcha` / `recaptcha` / `recaptcha-enterprise` / `turnstile` / `custom`. `New` switches `custom`, `recaptcha-enterprise`, and default `infoProviders` (siteverify). `Verifier.Pass` is `Pass(token, remoteIP string)`. Empty siteverify/assessments address omits the IP field. Identity owner is `GetRemoteIP` / `clientRequest.remoteIP` already passed into `ServeHTTP` / `Validate`. User-Agent owner is `r.UserAgent()`. Research: `knowledge/research/ext_eucaptcha_verify/`, `knowledge/research/ext_eucaptcha_widget/`. Upstream PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 is context only.

## Goals / Non-Goals

**Goals:**
- Add a `New` case that stores the official widget pairing and a verify verifier, without putting `eucaptcha` on siteverify.
- Classify HTTP 200 JSON with `success`/`train` the same family as assessments Error vs Reject.
- Reuse `GetRemoteIP` / `clientRequest.remoteIP` and `r.UserAgent()`; do not calculate either again.

**Non-Goals:**
- Porting PR 317's cache client, `FormValue`, Content-Type substring, HTTP 400 handling, `Validate` provider branch, or startup credential log.
- A `/verify-credentials` probe.
- Changing `captcha.html`, gate cookie format, or captcha routing.
- Applying empty-address reject to siteverify or assessments.
- Dropping `recaptcha-enterprise`.

## Decisions

1. `New` case beside `recaptcha-enterprise`, not `infoProviders`. Alternative: extend `infoProviders` with a verify URL — rejected; the JSON shape is not siteverify `secret`+`response`/`remoteip`.
2. File `pkg/captcha/eucaptcha.go` owns `eucaptchaVerifier`. Constant `configuration.EucaptchaProvider = "eucaptcha"`. Alternative: branch inside `Validate` — rejected; live spec `core_plugin_middleware_captcha-widget`.
3. Widen `Pass(token, remoteIP, userAgent string)`. Siteverify and assessments ignore `userAgent`. Alternative: put User-Agent on `clientRequest` — rejected; that fact does not always travel with the request cluster (`skill:opd-commandments:One job, one owner`; explore identity-owner Decision). Alternative: parse `User-Agent` inside the verifier from a stored `*http.Request` — rejected; `Pass` already takes the token and address as values.
4. Empty `remoteIP` is Pass-false with no POST on this verifier only. Production `ServeHTTP` already bans when `GetRemoteIP` fails; the verifier still guards the contract. Siteverify/assessments keep omit-when-empty.
5. Empty User-Agent is forwarded as `""`. Official field is necessary; the owner does not state HTTP for empty UA. Do not local-reject.
6. `train` decode uses `*bool`. Nil (JSON null or omitted key) is the false-or-null case. Explicit true is Pass-false. Alternative: treat omitted as reject — rejected; Desired names false or null.
7. Non-2xx (400/429/500) and undecodable JSON are the error return (re-render 200 challenge), same family as assessments. Do not special-case HTTP 400 as reject. Cap the response body the same way assessments does (64KiB).
8. Keep stock `captcha.html`. Official widget writes `eu-captcha-response`. Stock checkbox div already has `class`, `data-sitekey`, `data-callback="captchaCallback"`. Alternative: add a hidden input — rejected; Out of scope changing the stock page.
9. Reuse captcha `http.Client` / `captchaSiteverifyHTTPTimeoutSeconds`. `CaptchaSecretKey` stays required. Ownership already includes `Provider` and `SecretKey`; no new knobs.
10. Rejected: startup `/verify-credentials`. `train` true is the fail-closed path for wrong credentials / protection off.

## Risks / Trade-offs

- [Official samples use a submit button; stock page auto-submits via `captchaCallback`] → keep the stock callback; widget still injects the field after pass. If `data-callback` is ignored, the operator still has the injected field on a later POST.
- [Vendor page names `X-Forwarded-For` / `X-Client-IP`] → ignore those names; `GetRemoteIP` already chose `clientRequest.remoteIP`.
- [Vendor says always send `client_token`, including empty] → keep `Validate` `None` on empty token; do not POST. Desired and live widget spec.
- [Omitted `train` vs JSON null cannot be distinguished in Go `*bool`] → treat both as false-or-null (mint if `success`). Official examples always include `train`.
- [Allowlist error format lists tokens] → update the `fmt.Errorf` allowlist string and tests that match it.

## Migration Plan

Existing YAML is unchanged. Operators who want EU CAPTCHA set `captchaProvider: eucaptcha` with site key and secret. Roll back by reverting the provider token.

## Open Questions

None — ticket decisions stand on `explore.md`.
