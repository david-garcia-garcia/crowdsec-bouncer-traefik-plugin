## Context

See proposal.md — Why. Dest `Client.Validate(r)` always `PostForm`s urlencoded `secret`+`response` (`pkg/captcha/captcha.go`). `infoProviders` holds built-in js/key/response/validate only. Custom copies those four strings into a private `infoProvider`; `challengeURL` already lives on `Client`, not that map. `validateCaptcha` already requires the four custom strings when provider is `custom` and ignores leftover `CaptchaCustomChallengeURL` on built-ins. Dest `ServeHTTP(rw, r, remoteIP)` has the bouncer address for the gate cookie and calls `Validate(r)` without it. Cap Standalone official request is JSON `{"secret","response"}` (`knowledge/research/ext_capjs_standalone_siteverify/`). Official pages do not list request `remoteip`.

## Goals / Non-Goals

**Goals:**
- One Client field for the custom validate-body encoding, filled from `CaptchaCustomValidateBody` in `Client.New`.
- `validateCaptcha` rejects unknown tokens and `json` on a non-custom provider.
- JSON hop uses the same dest `httpClient`. Form hop stays `PostForm`.
- Absorb `remoteip` only if implement's `origin/master` sync already threads the address into `Validate`.

**Non-Goals:**
- A `trycap` provider, `captchaTrycapInstanceUrl`, or `<cap-widget>` template branch.
- Extra verify fields or headers beyond `secret`, `response`, and absorb-only `remoteip`.
- Splitting HTTP timeouts or changing backendbackoff.
- Inventing `Validate(r, remoteIP)` on current dest.
- Retargeting `examples/custom-captcha` or changing `cache.Client.Set` / dest gate cookie / dest reply `mime.ParseMediaType`.
- Closed PR #52 / #40.

## Decisions

1. Store the encoding on `Client` (sibling of `challengeURL`), not `infoProviders`. Built-ins share that map and always `PostForm`. Alternative: a `validateBody` field on `infoProvider` — rejected; the map is shared and built-ins never use the knob.
2. `bouncer.New` passes `config.CaptchaCustomValidateBody` into `Client.New` as one more string. Alternative: `Client` holds `*Config` — rejected; `New` already takes discrete strings.
3. `validateCaptcha` owns the token rules (it already distinguishes custom vs built-in). Alternative: `validateEnabledCaptchaSettings` — rejected; that helper is credentials, templates, and challenge URL after provider-set, not the custom-four-string gate.
4. After trim, exact lowercase `""` / `form` / `json`. `JSON` / `Form` fail as unknown. Alternative: case-insensitive tokens — rejected; explore assumed exact lowercase and README will say so.
5. JSON body is `encoding/json` of `secret` and `response` (plus `remoteip` only when Validate is given a non-empty address). Alternative: string format — rejected; must escape. Same dest `httpClient`; `http.NewRequest` + `Do` for JSON; keep `PostForm` for form/omit/built-in.
6. Do not invent `remoteip` on current dest. Identity owner is `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP` already on `ServeHTTP`. Implement syncs `origin/master` and adds the field on both encodings only if dest then has the argument. Alternative: always add `Validate(r, remoteIP)` now — rejected; explore identity-owner Decision and dest has no argument.
7. README: document `CaptchaCustomValidateBody` next to the other custom knobs, plus a CapJS custom example (`captchaCustomValidateUrl` + `captchaCustomResponse: cap-token` + `json`). Operator HTML stays theirs. Do not add a provider constant.

## Risks / Trade-offs

- [Sibling `2026-09-18-captcha-verify-template-ux` may land `remoteIP` on dest before implement] → implement syncs `origin/master` first and absorbs only that leftover; do not invent the argument.
- [`Client.New` signature grows by one string] → update `bouncer.New` and every test helper that calls `New`.
- [Built-in plus leftover `json` now fails startup] → intended; `""` / `form` on a built-in still pass.
- [Cap marketing says reCAPTCHA-compatible] → official request examples are JSON only; this knob sends that contract. Do not retarget Wicketkeeper.

## Migration Plan

Omit keeps today's `PostForm`. Operators who need Cap Standalone set `captchaProvider: custom` and `captchaCustomValidateBody: json`. Roll back by reverting the field; empty remains form.

## Open Questions

None — ticket decisions stand on `explore.md`.
