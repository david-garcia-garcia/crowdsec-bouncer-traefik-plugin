# Delivery

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
