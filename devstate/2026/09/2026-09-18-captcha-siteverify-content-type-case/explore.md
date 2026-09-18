# Explore

## Concepts

This ticket is only the siteverify response `Content-Type` match inside `Client.Validate`. After a solver POST, `ServeHTTP` calls `Validate`. A JSON body with `success:true` is supposed to mint `crowdsec_captcha_gate` and 302. On dest, `Validate` treats the provider response as JSON only when `Content-Type` has the lowercase prefix `application/json` (`strings.HasPrefix`). Any other casing logs `responseType:noJson` and returns `(false, nil)`. That pair is not an error: `ServeHTTP` writes the captcha HTML at 200 and does not mint the cookie.

```
solver POST token
        │
        ▼
   Client.Validate
        │
        ├─ Content-Type prefix application/json ──► decode JSON ──► success:true ──► cookie + 302
        │
        └─ any other casing (Application/JSON) ──► (false, nil) ──► 200 challenge, no cookie
```

Inbound captcha *form* `Content-Type` already goes through `mime.ParseMediaType` (type/subtype case-insensitive, parameters stripped). Siteverify does not. RFC 9110 § 8.3.1 already lives in `knowledge/research/ext_http_media-types/`: type and subtype are case-insensitive; the match is the type token *before parameters*.

CrowdSec does not own siteverify `Content-Type`. Built-in providers are hCaptcha, reCAPTCHA, and Turnstile; custom is an operator URL. The match rule is HTTP media type, not a CrowdSec wire field. No new research folder: the RFC packet answers the third-party fact this change needs.

Identity: this work does not set or reconstruct client address, user, tenant, Host, or trust hop. `remoteIP` is an argument to `ServeHTTP` / `mintGateValue`; `GetRemoteIP` stays the owner. No identity Open question.

Usage packets consumed: `core_plugin_middleware_captcha-gate` (cookie after successful verify) and `core_plugin_middleware_captcha-routing` (routing after the cookie). Neither owns the siteverify media-type match. Do not fold this defect into those units. No Language or usage write this phase (FindSpecHost has not named a host).

Bound: not GitHub #52, not inbound form parsing, not gate cookie format, not provider URLs/keys/body, not siteverify HTTP status (sibling), not other packages.

### Reproduction

Claimed failure: `TestHunt_siteverifyJSONContentTypeIsCaseInsensitive` — siteverify `Application/JSON` + `{"success":true}` must 302 and set `crowdsec_captcha_gate`.

**Reproduced.** Throwaway test in this worktree (deleted after the run; not committed): custom provider, stub siteverify `Content-Type: Application/JSON` and body `{"success":true}`, POST `dummy-captcha-response=ok`.

- `go test ./pkg/captcha -run TestHunt_siteverifyJSONContentTypeIsCaseInsensitive -count=1` → **FAIL** — `solve want 302, got 200 E2E_CAPTCHA_PAGE_MARKER`
- Control: `go test ./pkg/captcha -run Test_ServeHTTP_dummyProviderSolveIssuesGateCookie -count=1` → **ok** (same path, lowercase `application/json`)

The hunt name is proof, not a dest file. Dest still needs a committed `zzz_` regression.

## Decisions

- Fix the `Validate` media-type check (the shared owner), not a `ServeHTTP` special case.
- Treat as JSON when the type token before parameters equals `application/json` case-insensitively. `success:true` on that path keeps today's cookie + 302.
- Reuse `mime.ParseMediaType` already in this file; do not invent a second matcher.
- One regression under `pkg/captcha/` with a `zzz_` basename. Hunt function name may stay as the proof name.
- Propose runs FindSpecHost. Do not fold into captcha-routing or captcha-gate.
- No identity reconstruction. No research write. No usage write this phase.

## Open questions

- Q: Which helper should `Validate` use to read the siteverify media type?
  Decision: assumed — call `mime.ParseMediaType` on the response `Content-Type` (already used for inbound form in this file) and compare the type token to `application/json`. Do not keep `strings.HasPrefix` and do not add a parallel EqualFold helper.
  By: explore

- Q: Where should the dest regression live, and may it keep the hunt name?
  Decision: assumed — add a `zzz_*_test.go` under `pkg/captcha/` (existing `zzz_servehttp_test.go` or a new `zzz_` file). The function may keep `TestHunt_siteverifyJSONContentTypeIsCaseInsensitive`. Do not copy a hunt worktree file as dest.
  By: explore

- Q: Which spec unit owns the siteverify media-type match?
  Decision: resolved — FindSpecHost new `core_plugin_middleware_captcha-siteverify` (high). Candidates: `core_plugin_middleware_captcha-routing`, `core_plugin_middleware_captcha-gate`, `core_plugin_middleware_config-validation`, `core_plugin_middleware_bouncer`. Do not fold into routing or gate.
  By: propose

- Q: Does this change also treat a non-2xx siteverify HTTP status as failure?
  Decision: resolved — no. Out of scope. Sibling defect. This change does not inspect status.
  By: explore

- Q: Does this change also reject `application/jsonp` and other HasPrefix false-friends as extra work?
  Decision: resolved — no extra cases. Equals-before-parameters will reject `application/jsonp` as a side effect of the required match. Do not expand the ticket to hunt other prefixes.
  By: explore

- Q: If siteverify omits `Content-Type` but the body is `{"success":true}`, should `Validate` treat it as JSON?
  Decision: resolved — no. Desired is the media-type match only. Missing or non-JSON type stays `(false, nil)` and the 200 challenge.
  By: explore
