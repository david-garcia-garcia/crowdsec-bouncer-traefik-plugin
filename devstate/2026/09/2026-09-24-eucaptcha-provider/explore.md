# Explore

## Concepts

This change adds provider token `eucaptcha` as a first-class captcha pairing. It is not a siteverify sibling and not a port of https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 (context only; that diff is out of scope).

Units this change would touch:

- **Config allowlist** — `pkg/configuration/configuration.go` `validateCaptcha` / `HcaptchaProvider` constants. Job: accept `eucaptcha` without dropping `recaptcha-enterprise`.
- **Widget + verifier pairing** — `pkg/captcha/captcha.go` `New`. Job: the only provider switch. Pair stored Widget with a new verify verifier. Do not put `eucaptcha` in `infoProviders` (that map is siteverify).
- **Verifier contract** — `pkg/captcha/verifier.go` `Pass`. Job: classify a posted token. Affected names this surface for User-Agent and empty address.
- **Siteverify verifier** — `pkg/captcha/siteverify.go`. Job: stays hcaptcha / recaptcha / turnstile / custom. Not the eucaptcha owner.
- **Assessments verifier** — `pkg/captcha/assessments.go`. Job: recaptcha-enterprise only. Ignore a new User-Agent argument.
- **Gate cookie** — `pkg/captcha/gate.go`. Job: mint on `Validate` `Pass` only. No train knowledge.
- **Stock challenge page** — `captcha.html`. Job: stay one file. Checkbox branch already has `data-sitekey`, `data-callback="captchaCallback"`, class `{{ .FrontendKey }}`. Score branch keeps `g-recaptcha-response`.
- **Client address owner** — `pkg/ip/checker.go` `GetRemoteIP` plus `pkg/bouncer/clientrequest.go`. Job: already chosen `req.remoteIP` on the challenge handler.
- **User-Agent owner** — inbound `*http.Request` (`UserAgent()`). Not on `clientRequest`. Not the LAPI plugin User-Agent in `pkg/lapi/client_http.go`.

```
  GetRemoteIP → clientRequest.remoteIP ──┐
  http.Request.UserAgent() ──────────────┤
                                         ▼
  New ──► Widget (script, class, TokenField)
       └► eucaptchaVerifier.Pass(token, remoteIP, userAgent)
              POST https://api.eu-captcha.eu/v1/verify
              Pass true only if success && train is false or null
                                         ▼
  Validate (no provider name) → ServeHTTP mint gate / render
```

Call sites that matter (roots searched: `pkg/captcha`, `pkg/configuration`, `pkg/bouncer`, `README.md`, `openspec/specs`, `knowledge/devdocs`):

- `Verifier.Pass`: 2 implementers (`siteverify.go`, `assessments.go`), 1 production call (`captcha.go` `Validate`). Zero direct test calls of `.Pass(` under `pkg/captcha`.
- `infoProviders`: 1 map + `New` default branch (`captcha.go`). Three keys today (hcaptcha, recaptcha, turnstile).
- `New` switch: 1 function, three cases (`custom`, `recaptcha-enterprise`, default).
- Provider allowlist: 1 `contains` + error format (`configuration.go` `validateCaptcha`); tests `Test_validateCaptcha`, `TestValidateParams_RecaptchaEnterprise` (`Unknown provider still fails`); README `CaptchaProvider` expected values; live specs `core_plugin_middleware_captcha-enterprise-config` (allowlist + unknown-token scenario) and `core_plugin_middleware_config-validation` (two empty-secret scenarios that list built-ins); usage `core_plugin_middleware_captcha-enterprise-config.md` allowlist bullet.

Reproduce: not reproduced as a failing request. Dest has no `eucaptcha` path. Measured: `go test ./pkg/configuration -run "Test_validateCaptcha|TestValidateParams_RecaptchaEnterprise" -count=1` passed; unknown token still fails `CaptchaProvider`; `validateCaptcha` allowlist is empty / hcaptcha / recaptcha / recaptcha-enterprise / turnstile / custom (`configuration.go`).

Outside facts: `knowledge/research/ext_eucaptcha_verify/`, `knowledge/research/ext_eucaptcha_widget/` (official docs.eu-captcha.eu, fetched 2026-09-24). In-tree: captcha widget / siteverify / assessments / gate / routing / ip packets. Not used as API measurement: caller chat; PR 317.

## Decisions

- Chosen seam: add `configuration.EucaptchaProvider = "eucaptcha"` and a `New` case (same place as `recaptcha-enterprise`), storing Widget `{ScriptURL: https://cdn.eu-captcha.eu/verify.js, Class: eu-captcha, TokenField: eu-captcha-response, RetryAfterReject: true}` and a new `eucaptchaVerifier` that POSTs JSON to `https://api.eu-captcha.eu/v1/verify`.
- Chosen: keep `captcha.html` unchanged. Official widget injects `eu-captcha-response`. Stock checkbox div already supplies class, `data-sitekey`, and `data-callback="captchaCallback"` (submits after pass). Official samples use a submit button and do not name `captchaCallback`; they do call `data-callback` after the challenge passed.
- Chosen: `Validate` stays provider-blind. Empty token stays `None` (do not POST), even though the vendor says always send `client_token` including empty.
- Chosen: mint stays `ServeHTTP` on `Pass`. The new verifier returns Pass-true only when HTTP 200 JSON has `success` true and `train` is JSON false or null (`knowledge/research/ext_eucaptcha_verify/`). `train` true is Pass-false (no cookie), matching Desired and official “skipped / wrong credentials / protection off”.
- Chosen: empty client address is a reject on **this verifier only** (no vendor POST). Siteverify and assessments keep omit-when-empty. Production `ServeHTTP` already bans before captcha when `GetRemoteIP` fails or `ipAddr` is nil; the verifier still guards the contract.
- Chosen: forward `Validate`’s `remoteIP` (already `clientRequest.remoteIP` after `GetRemoteIP` / `ipAddr.String()`). Do not parse `X-Forwarded-For`, `X-Real-Ip`, or `X-Client-IP` in captcha even though the vendor page names those headers.
- Chosen: forward `r.UserAgent()` from the challenge request into `Pass`. Do not put User-Agent on `clientRequest`. Do not send the LAPI plugin User-Agent.
- Chosen: widen `Pass(token, remoteIP, userAgent string)`. Siteverify and assessments ignore `userAgent`. Cited by Affected `pkg/captcha/verifier.go` — `Pass` surface (User-Agent / empty address). Call sites enumerated above.
- Chosen: keep `recaptcha-enterprise`. Ticket lists eucaptcha beside hcaptcha/recaptcha/turnstile/custom and does not ask to drop enterprise.
- Chosen: no `/verify-credentials` startup probe. `train` is the fail-closed path.
- Chosen: HTTP 200 bodies classified by `success`/`train`; non-2xx or undecodable JSON is the error return (re-render 200 challenge), same family as assessments. Do not port PR 317 HTTP 400 / `FormValue` / cache / Validate branch / credential log.
- Chosen: `CaptchaSecretKey` stays required for `eucaptcha` (vendor `secret` is necessary). Reuse captcha `http.Client` / `captchaSiteverifyHTTPTimeoutSeconds`. Send `Content-Type: application/json` (embed/iOS samples; verify page omits the header name).
- Rejected: `infoProviders` + siteverify for eucaptcha — validate URL and JSON shape are not siteverify (`secret`+`response` / `remoteip`).
- Rejected: provider branch inside `Validate` — live spec `core_plugin_middleware_captcha-widget`; Out of scope as a PR 317 port.
- Rejected: changing stock `captcha.html` to add `eu-captcha-response` — Out of scope; widget injects the field.
- Rejected: applying empty-address reject to siteverify/assessments — Desired is this vendor; dest omit-when-empty stays.
- Live contract: fold `openspec/specs/core_plugin_middleware_captcha-widget` (New pairing + TokenField), `core_plugin_middleware_config-validation` (allowlist / secret-required lists), `core_plugin_middleware_captcha-enterprise-config` (allowlist scenarios must keep `recaptcha-enterprise` and add `eucaptcha`). New leaf for eucaptcha verify HTTP (same family as `core_plugin_middleware_captcha-assessments`). Do not ADDED “eucaptcha is absent from siteverify”; that spec already names only hcaptcha/recaptcha/turnstile/custom encodings. README `CaptchaProvider` expected values.

## Open questions

- Q: Who already owns client address and User-Agent for the eucaptcha verify POST?
  Rank: additive asked — new JSON fields this provider would emit; Desired “Forward the client address Validate already receives, and the request User-Agent”; skill One job, one owner
  Decision: resolved — client address owner is `GetRemoteIP` / `clientRequest.remoteIP` (`pkg/ip/checker.go`, `pkg/bouncer/clientrequest.go`, written onto the challenge handler in `pkg/bouncer/bouncer.go`). Reuse that `remoteIP`; captcha must not re-parse forwarded headers. User-Agent owner is the inbound `*http.Request` the host already built (`r.UserAgent()`). Reuse that header. Not Traefik ipstrategy, not a second XFF walk, not LAPI `Crowdsec-Bouncer-Traefik-Plugin/…` (`pkg/lapi/client_http.go`). User-Agent stays off `clientRequest` (that type is request + chosen address only).
  By: explore

- Q: What is the vendor widget script URL and CSS class?
  Rank: additive asked — new Widget pairing this change creates; Desired “Pairing for this provider supplies the vendor widget (script URL, CSS class, …)”
  Decision: resolved — script `https://cdn.eu-captcha.eu/verify.js`, class `eu-captcha` (`knowledge/research/ext_eucaptcha_widget/`, official HTML and JavaScript / embed-widget pages).
  By: explore

- Q: Does the vendor widget inject hidden field `eu-captcha-response` so stock `captcha.html` needs no extra field?
  Rank: additive asked — TokenField on the pairing this change creates; Desired hidden field `eu-captcha-response`; Out of scope “Changing the stock challenge page”
  Decision: resolved — yes; `verify.js` writes `eu-captcha-response` itself. Canonical samples are a form with only the `eu-captcha` div (no pre-existing hidden input). Keep `captcha.html`. `TokenField` is `eu-captcha-response`. (`knowledge/research/ext_eucaptcha_widget/`)
  By: explore

- Q: What are the exact JSON types, HTTP statuses, and error bodies for `/v1/verify`?
  Rank: additive asked — new verifier this change creates; Desired POST `https://api.eu-captcha.eu/v1/verify` with JSON `sitekey`, `secret`, `client_ip`, `client_token`, `client_user_agent`
  Decision: resolved — five necessary string fields on JSON POST to `https://api.eu-captcha.eu/v1/verify`; HTTP 200 body `success` boolean, `train` boolean or null, `error-codes` array only with `success` false; statuses 200 / 400 / 429 / 500; 400–500 share one example `{"error":"missing_field","message":"Required field 'sitekey' is missing."}`. Follow the verify page over embed-widget’s `"token"` sample. Non-2xx or undecodable JSON → error return. (`knowledge/research/ext_eucaptcha_verify/`)
  By: explore

- Q: Is an empty User-Agent a rejection the same way as an empty client address?
  Rank: additive asked — new verifier this change creates; Unknowns on requirement.md; Desired names empty **address** as rejection only
  Decision: assumed — no. Forward `r.UserAgent()` including empty string. Do not local-reject empty UA. Official field is necessary but the owner does not state HTTP for empty/missing UA (`knowledge/research/ext_eucaptcha_verify/`). Empty client address stays a local reject on this verifier.
  By: explore

- Q: How is `train` encoded when absent vs explicit false vs JSON null?
  Rank: additive asked — Desired “Mint the gate cookie only when success is true and train is false or null”
  Decision: assumed — Pass-true only when `success` is true and `train` is JSON `false` or JSON `null`. Explicit `true` is Pass-false. Omitted key: Go `*bool` cannot tell omit from null; treat nil `*bool` as the false-or-null case (mint if `success`). Official examples always include `train: false` or `train: true`; omit vs null is not shown (`knowledge/research/ext_eucaptcha_verify/`).
  By: explore

- Q: What is the blast radius on live specs that freeze the current provider list?
  Rank: bounded asked — existing allowlist contract with enumerated callers; Unknowns “Blast radius on live specs”; Affected names `config-validation`, `captcha-widget`, `captcha-siteverify`
  Decision: resolved — migrate the enumerated sites above in this change. Fold widget, config-validation, and enterprise-config allowlist (keep `recaptcha-enterprise`, add `eucaptcha`). New verify spec leaf. Siteverify spec stays the three urlencoded built-ins; do not list eucaptcha there.
  By: explore

- Q: Does dest drop `recaptcha-enterprise` because the ticket listed eucaptcha beside hcaptcha/recaptcha/turnstile/custom only?
  Rank: additive asked — Tension on requirement.md; Desired “beside hcaptcha, recaptcha, turnstile, and custom”; ticket does not ask to drop enterprise
  Decision: resolved — keep `recaptcha-enterprise`. Add `eucaptcha` to the allowlist. Secret stays required for eucaptcha (not the enterprise empty-secret exception).
  By: explore

- Q: Should empty client address reject on every `Pass` implementer, or only eucaptcha?
  Rank: additive asked — Desired “An empty client address is a rejection”; Affected Pass surface; siteverify live spec says omit `remoteip` when empty
  Decision: assumed — eucaptcha verifier only. Siteverify and assessments keep omit-when-empty. Do not rewrite those specs for this ticket.
  By: explore
