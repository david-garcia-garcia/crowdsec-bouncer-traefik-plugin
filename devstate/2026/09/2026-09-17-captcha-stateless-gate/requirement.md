# Requirement
IssueKey: 2026-09-17-captcha-stateless-gate

## Problem
Captcha grace after a successful provider solve is stored in the shared cache keyed by client IP (`{ip}_captcha`). That ties grace to cache availability, shared-IP semantics, and cross-tab behavior; PR #45 proposed cache-backed session tokens instead. This ticket replaces grace with a signed HTTP cookie and drops cache use in `pkg/captcha`.

## Current (code)
- `pkg/captcha/captcha.go` — on valid solve, `Set(remoteIP+"_captcha", CaptchaDoneValue, gracePeriodSeconds)`; `Check(remoteIP)` reads that key (`103-104`, `126-130`).
- `pkg/captcha/captcha.go` — `New` requires `*cache.Client`; no cookie issuance or HMAC validation (`68-90`).
- `pkg/bouncer/bouncer.go` — wires `lapiClient.Cache()` into captcha `New`; remediation calls `Check(req.remoteIP)` then `ServeHTTP` with IP only (`85-101`, `292-298`).
- `pkg/configuration/configuration.go` — `CaptchaGracePeriodSeconds` default 1800; `CaptchaSecretKey` is provider siteverify only; no bind-IP/cookie-only knob or dedicated HMAC secret (`112-123`, `193-194`).
- `pkg/ip/checker.go` — `GetRemoteIP` / `parseIP` use `net.ParseIP` for chosen address (`84-90`, `133-144`); no captcha-specific normalization helper.
- `openspec/specs/core_cache_client_isolated-store/spec.md` — requires `{ip}_captcha` → `d` in cache after solve (`38-43`).
- GitHub PR #45 (`2026-09-06-upstream-353-captcha-session-cookie`) — OPEN; cache token `{remoteIP}_captcha_{token}` design (supersede, do not merge).

## Desired
- After successful provider verify, set an HttpOnly signed cookie (HMAC with dedicated plugin secret, not `CaptchaSecretKey`): payload includes version, `issued_at`, optional bind-IP flag, normalized IP when bound; validate with constant-time HMAC, expiry against `CaptchaGracePeriodSeconds`, optional IP match via same normalization as `GetRemoteIP`.
- Public config: bind gate to IP+cookie vs cookie-only (HMAC + expiry always).
- `pkg/captcha` must not read/write any cache grace keys; stale cache grace must not pass `Check`.
- Cookie attributes: Path=/, SameSite=Lax, MaxAge=grace, Secure when TLS, no Domain unless required; cookie name (not forgeable header).
- Close PR #45 without merging; do not continue its session-store design.

## Affected
- `pkg/captcha`, `pkg/bouncer`, `pkg/configuration` (new secret + bind knob), tests, OpenSpec `core_cache_client_isolated-store` (captcha grace cache requirement), operator docs/examples as needed.

## Out of scope
- Removing Redis or decision/stream cache usage.
- Binding User-Agent or HTTP protocol on the cookie.
- Changing decision storage (memory vs Redis).
- Merging or extending PR #45 cache-token sessions.

## Unknowns
- Exact cookie name, payload encoding (JSON vs compact binary), and dedicated secret config field name / generation story.
- Whether `Check`/`ServeHTTP` should take `*http.Request` (for cookie + TLS) vs extending bouncer call sites only.
- IPv6 “normalization” contract beyond `net.ParseIP` string form when comparing bound IP.

## Tensions
- OpenSpec still mandates cache `{ip}_captcha` → `d`; ticket forbids cache grace — spec must change in propose/implement.
- PR #45 OPEN on alternate design — human/process: close when implementing this ticket.
- `CaptchaDoneValue` and cache wiring in `New` become dead surface once grace is cookie-only — remove or narrow in same change.
