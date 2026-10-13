# Requirement
IssueKey: 2026-09-18-captcha-siteverify-content-type-case

## Problem
Provider siteverify that returns `Application/JSON` plus `{"success":true}` is treated as non-JSON. The solver gets a 200 challenge and no `crowdsec_captcha_gate` cookie.

## Current (code)
- `Client.Validate` accepts JSON only when `Content-Type` has prefix `application/json` (`strings.HasPrefix`). Any other casing logs `responseType:noJson` and returns `(false, nil)`. `pkg/captcha/captcha.go`
- `(false, nil)` from `Validate` is not an error: `ServeHTTP` writes the captcha HTML at 200 and does not mint the gate cookie or 302. `pkg/captcha/captcha.go`
- `(true, nil)` mints `crowdsec_captcha_gate` via `setGateCookie` and `http.Redirect` 302 to `r.URL.String()`. `pkg/captcha/captcha.go` `pkg/captcha/gate.go`
- Existing solve tests stub siteverify with lowercase `application/json` only. `pkg/captcha/zzz_servehttp_test.go`
- Inbound captcha *form* `Content-Type` already uses `mime.ParseMediaType` (case-insensitive type/subtype). Siteverify response does not. `pkg/captcha/captcha.go`
- RFC 9110 § 8.3.1: type and subtype tokens are case-insensitive; parameters follow `;`. `knowledge/research/ext_http_media-types/notes.md`

## Desired
- Treat siteverify as JSON when the media type *before parameters* equals `application/json` case-insensitively.
- `success:true` on that path must set the gate cookie and 302 (same as today's lowercase `application/json` path).
- One regression test for `Application/JSON` + `{"success":true}` (hunt name `TestHunt_siteverifyJSONContentTypeIsCaseInsensitive` is proof, not a dest file).
- This defect only.

## Affected
- `pkg/captcha/captcha.go` (`Validate` Content-Type check)
- captcha unit tests under `pkg/captcha/` (add regression)

## Out of scope
- GitHub #52
- Inbound form `Content-Type` parsing (`formFieldValue` / `mime.ParseMediaType`)
- Gate cookie format, bind-IP, Secure, Cache-Control on the 200 challenge
- Provider URLs, keys, or siteverify request body
- Changing `HasPrefix` false-friends (`application/jsonp`) unless required to implement the equals-before-parameters match
- Other packages

## Unknowns
- None that block the ask. Helper (`mime.ParseMediaType` vs `EqualFold` on the type token) is implementer's, not a new product requirement.

## Tensions
- Ticket line `pkg/captcha/captcha.go:324-327` matches dest `Validate` on `origin/master` (`fad36a1`).
- Proven FAIL test lives only in the hunt worktree, not on dest. Dest needs a committed regression, not the hunt file as-is.
