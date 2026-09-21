# Explore
IssueKey: 2026-09-17-captcha-request-routing

Measured on dest `handleRemediationServeHTTP` (`pkg/bouncer/bouncer.go`) and `pkg/captcha`. `TestCaptchaMethodBasedLogic` passed (`go test ./pkg/bouncer/ -run TestCaptchaMethodBasedLogic`): it re-encodes `kind == captcha && Method != HEAD`, so HEAD + captcha is still the ban fallback. No `comments.md`. `openspec list --json`: no active change. Consumed `knowledge/devdocs/index.md`, `knowledge/research/index.md`, `index_core_plugin.md`, `core_plugin_middleware.md`, `core_plugin_middleware_captcha-gate.md`. No `priority: always` packets. No research write (routing is in-tree; custom widget URLs are operator config). Did not open `pkg/lapi` or `pkg/reclaim`.

## Concepts

`handleRemediationServeHTTP` is the only place that turns a captcha/ban verdict into a response. Today:

```
kind captcha AND captcha.Valid AND Method != HEAD
  Check(cookie) true  → handleNextServeHTTP (origin, AppSec on)
  Check false         → captcha.ServeHTTP (validate or HTML)
else
  ban
```

```
                    handleRemediationServeHTTP
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
     captcha + Valid + !HEAD                 ban
              │
     ┌────────┴────────┐
     ▼                 ▼
  Check true        Check false
     │                 │
     ▼                 ▼
   origin           ServeHTTP
   (POST too)     first-solve 302
                    or HTML
```

Three holes versus Desired:

1. **Solved-form POST.** First-solve POST already 302s inside `ServeHTTP` after `Validate` + gate cookie. The remaining hole is **Check true** (cookie already set) plus a captcha-form POST (second tab). That POST is forwarded as POST. GET-only origins answer 405. `#48` named `IsCaptchaFormPost` / `WriteSolvedRedirect`; dest does not have them. Dest already has unexported `captchaResponseFromRequest` (query / POST form / raw body, restores `Body`, 1MiB cap) used by `Validate`.

2. **Custom challenge resources.** Custom provider stores `BouncerCaptchaCustomJsURL` as `infoProvider.js`. Browser-facing dest keys: JsURL only. `BouncerCaptchaCustomValidateURL` is server-side siteverify (plugin → provider), not a browser fetch. Built-in hcaptcha/recaptcha/turnstile JS is on vendor CDNs and never hits this middleware. Same-origin custom JS/widget **does**. Those requests are captcha-kind, Check false, so they get captcha HTML instead of the asset. Ban must stay blocked. `#50` matched exact path of JsURL plus optional `bouncerCaptchaCustomChallengeUrl`; dest has no challenge-URL key. `examples/custom-captcha/captcha.html` hardcodes `data-challenge-url=.../v0/challenge` (second path). Default `captcha.html` has no ChallengeURL.

3. **HEAD.** `Method != HEAD` drops captcha HEAD to ban. `TestCaptchaMethodBasedLogic` expects that. Ticket Desired: treat HEAD like the GET it previews on the captcha path (every captcha URL, not only custom-resource). `#50` assumed only matching custom-resource HEAD passes and other captcha HEAD stays ban — that loses to this ticket.

Past-captcha is `Check(req, remoteIP)` and the HMAC gate cookie only (`core_plugin_middleware_captcha-gate`). No `{ip}_captcha` cache grace. `Client.New` already takes `gateSecret` and `gateBindIP`.

Identity: `ServeHTTP` calls `ip.GetRemoteIP` and stores the string on `clientRequest.remoteIP`. `Check` already receives that owner output. This work does not reconstruct address, user, tenant, Host, or trust hop.

Process lifetime: this ticket is request routing in one handler. Not `New`, shared ticker, cache, or HTTP client. No `sync.Once` / package globals.

Spec map family is `core_plugin_middleware_*`. `core_plugin_middleware_captcha-gate` owns cookie + first-solve 302. It does not own Check-path form POST, custom-resource passthrough, or HEAD. `#48`/`#50` leaves `core_plugin_captcha_solved-form-post` / `core_plugin_captcha_custom-resource-passthrough` are not on dest and sit in a `captcha` component the map does not have.

Intended routing after this change:

```
kind captcha AND captcha.Valid
  custom-resource path     → handleNextServeHTTP
  Check true + form POST   → 302 same URL (no origin POST)
  Check true               → handleNextServeHTTP
  else                     → captcha.ServeHTTP  (HEAD included)
else
  ban
```

## Decisions

- Detect the solved form with a `captcha.Client` predicate that calls existing `captchaResponseFromRequest`. Do not add `#48`'s second 64KiB body reader.
- Custom-resource match is exact `req.URL.Path` of configured **browser** URLs: required `BouncerCaptchaCustomJsURL`, plus optional `bouncerCaptchaCustomChallengeUrl`. Ignore host and query. No prefix. Never `BouncerCaptchaCustomValidateURL`. Custom-provider-only (built-in CDN paths are not a match set).
- Add optional public key `bouncerCaptchaCustomChallengeUrl` so a second widget path (wicketkeeper-style `/fast.js` + `/v0/challenge`) can pass without a prefix bypass. Empty = JsURL path only. Do not require it in custom-provider validation. Do not wire template `ChallengeURL`.
- Remove `Method != HEAD` for the whole captcha kind. Custom-resource HEAD still hits the passthrough first. Other captcha HEAD goes to `ServeHTTP`, not ban.
- Passthrough and Check-true ordinary requests use `handleNextServeHTTP` (AppSec still runs). Ban kind never passthrough.
- `Check` stays cookie-only. Reuse `req.remoteIP`. Do not touch `pkg/lapi` or `pkg/reclaim`.
- Spec the routing table on a new `core_plugin_middleware_*` leaf (propose FindSpecHost). Keep captcha-gate as cookie/first-solve owner. Cite #48 and #50 on the PR body only.
- Tests that fail before the fix: Check-true form POST → 302 not origin; ordinary POST without the response field → origin; custom JS/challenge path under captcha → origin; same path under ban → ban; HEAD + captcha → captcha path not ban. Replace the tautological `TestCaptchaMethodBasedLogic` with handler tests.

## Open questions

- Q: Who already owns the client address used by `Check` and gate bind-IP?
  Decision: resolved — `ip.GetRemoteIP` in bouncer `ServeHTTP`; the string lives on `clientRequest.remoteIP`. Reuse that output. Do not re-parse `RemoteAddr` or rebuild Host/trust hop.
  By: explore

- Q: What is the passthrough match set — `BouncerCaptchaCustomJsURL` path only, or also a widget/challenge URL?
  Decision: assumed — exact path of `BouncerCaptchaCustomJsURL` and, when set, exact path of optional `bouncerCaptchaCustomChallengeUrl`. Not `BouncerCaptchaCustomValidateURL`. Not a directory prefix.
  By: explore

- Q: Does that need a new optional public key?
  Decision: assumed — yes, optional `bouncerCaptchaCustomChallengeUrl` / `BouncerCaptchaCustomChallengeURL`. Empty means no second path. Custom validation still requires the existing four custom fields only.
  By: explore

- Q: Path vs host vs prefix matching, and why that scope is safe?
  Decision: assumed — `url.Parse` the configured URL, compare `parsed.Path` to `req.URL.Path` (must be non-empty and start with `/`). Ignore host and query so absolute config URLs still match a same-route asset path. Exact path only: a request cannot smuggle `/admin` or a prefix of the JS directory. Cross-origin widget hosts never hit this middleware; passthrough only matters for same-route paths the operator listed.
  By: explore

- Q: Export `captchaResponseFromRequest` vs a wrapper?
  Decision: resolved — keep it unexported. Add `Client.IsCaptchaFormPost` that is POST + non-empty `captchaResponseFromRequest` for `infoProvider.response`. Bouncer calls that owner. Query-only tokens on GET are not a form POST.
  By: explore

- Q: HEAD-like-GET for every captcha URL, or only custom-resource paths?
  Decision: resolved — every captcha-kind URL. Drop `Method != HEAD`. `#50`'s "other HEAD stays ban" and `TestCaptchaMethodBasedLogic` lose to ticket Desired.
  By: explore

- Q: Should the Check-true form POST remint the gate cookie or hit the provider again?
  Decision: assumed — neither. Cookie already valid. `WriteSolvedRedirect` only: `StatusFound` to `req.URL.String()`, set `solved-captcha` remediation header when configured. Same 302 as first-solve. Do not change first-solve `Validate` behavior.
  By: explore

- Q: Should custom-resource passthrough skip AppSec?
  Decision: assumed — no. Use `handleNextServeHTTP`.
  By: explore

- Q: Which spec leaf owns `handleRemediationServeHTTP` routing?
  Decision: resolved — new `core_plugin_middleware_captcha-routing` (FindSpecHost: new, high). Candidates: `core_plugin_middleware_captcha-gate`, `core_plugin_middleware_bouncer`, `core_plugin_middleware_config-validation`, misnamed `core_plugin_captcha_*`. Do not fold. Do not recreate the `captcha` component. 4th part is `captcha-routing`, not the change kebab.
  By: propose

- Q: Wire `#50` template `ChallengeURL` into default/example HTML?
  Decision: resolved — no. Out of scope. Operators keep a hardcoded challenge URL in their template if the widget needs one.
  By: explore
