## Context

See proposal.md — Why. `handleRemediationServeHTTP` currently: captcha kind and not HEAD → grace `Check` then captcha HTML; HEAD captcha → ban. Custom JS URL is only a template `FrontendJS`. Challenge URL is not config. Client IP is already on `clientRequest.remoteIP`.

## Goals / Non-Goals

**Goals:**
- One match owner on captcha Client; bouncer only asks and routes.
- Reuse `handleNextServeHTTP` (AppSec stays on the pass path).
- Parse resource paths once at captcha `New`.

**Non-Goals:**
- Pass-through for hcaptcha/recaptcha/turnstile CDN URLs.
- Pass-through of `CaptchaCustomValidateURL`.
- Changing unmatched captcha HEAD → ban.
- Reclaim / process-lifetime changes.
- Parsing `RemoteAddr` on this path.

## Decisions

1. **Path match lives on captcha Client.** `infoProvider` (or Client fields filled only for custom) stores JS and challenge *paths* parsed at `New`. A method on Client answers “is this request a custom resource?” Bouncer calls it from `handleRemediationServeHTTP` before captcha HTML and before the HEAD→ban skip. Alternative: string compare in bouncer — rejected; bouncer does not own those URLs.

2. **Parse at `New`, compare `req.URL.Path` at request time.** `url.Parse` each configured value; keep `Path` when it starts with `/`. Invalid or empty → no match for that slot. Alternative: prefix match — rejected; `/v0` would leak unrelated origin paths. Alternative: host+path — rejected; example JS URLs use an origin Host the browser never sends.

3. **`CaptchaCustomChallengeURL` optional.** Do not add it to the four required custom fields. Alternative: required — rejected; existing Traefik labels would fail ValidateParams.

4. **Pass-through before HEAD skip, captcha kind only.** Order: if captcha kind and custom resource match → `handleNextServeHTTP`; else existing HEAD/Check/HTML. Ban kind never inspects those URLs. Alternative: skip AppSec on this pass — rejected; ticket asked origin reach via the existing pass path.

5. **`captcha.Client.New` gains one argument** (challenge URL) next to JS URL. Alternative: a captcha options struct — rejected; one sibling field, Bound the ask.

6. **Template key `ChallengeURL`.** Same execute map as `FrontendJS`. Default `captcha.html` unchanged. Custom example uses `{{ .ChallengeURL }}`.

## Risks / Trade-offs

- [Path-only match if two apps share `/fast.js` on one middleware] → Operators set distinct paths; no host filter by design.
- [Optional challenge URL leaves `/v0/challenge` blocked until set] → README + example label; not a silent required-field break.
- [AppSec can still block the widget] → Same as any pass; out of scope to bypass.

## Migration Plan

Plugin version bump. Operators with custom captcha on the same protected router set `captchaCustomChallengeUrl` (and already have `captchaCustomJsUrl`). Rollback: previous tag ignores the new YAML key (Traefik omits unknown). No cache or Redis shape change.

## Open Questions

None. Explore decisions are in `devstate/explore.md`.
