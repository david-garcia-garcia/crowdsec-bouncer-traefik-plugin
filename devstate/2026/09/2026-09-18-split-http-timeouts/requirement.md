# Requirement
IssueKey: 2026-09-18-split-http-timeouts

## Problem
One public `httpTimeoutSeconds` (default 10) is the transport Timeout for LAPI, AppSec, and captcha siteverify. An AppSec hang waits the same duration as a LAPI stream GET. Upstream context: maxlerebourg/crowdsec-bouncer-traefik-plugin#388.

## Current (code)
- Public `HTTPTimeoutSeconds` / `httpTimeoutSeconds`, default 10, `validateParamsRequired` rejects `< 1`. Path: `pkg/configuration/configuration.go`.
- No `LapiHttpTimeoutSeconds`, `AppsecHttpTimeoutSeconds`, or `BouncerCaptchaHttpTimeoutSeconds`. Path: not found.
- No `EffectiveLapi` / `EffectiveAppsec` / `EffectiveCaptcha` inherit helpers. Only `EffectiveFailureAction`. Path: `pkg/configuration/configuration.go`.
- LAPI `newTransport` sets `http.Client.Timeout` and `httpTimeoutSeconds` from raw `config.HTTPTimeoutSeconds`. Path: `pkg/lapi/client_http.go`.
- AppSec `newTransport` does the same from raw `config.HTTPTimeoutSeconds`. Path: `pkg/appsec/client_http.go`.
- Captcha siteverify `http.Client` Timeout is `config.HTTPTimeoutSeconds` at Bouncer construct. Path: `pkg/bouncer/bouncer.go`.
- Captcha `Client.New` stores that `*http.Client`; it does not pick a timeout itself. Path: `pkg/captcha/captcha.go`.
- `AdoptTransport` last-writes a new transport and idle-closes the previous client; `fieldsDiffer` includes `httpTimeoutSeconds`. Paths: `pkg/lapi/client_http.go`, `pkg/appsec/client_http.go`.
- Session tests already assert a shared `HTTPTimeoutSeconds` change adopts Timeout and reuses the Client. Paths: `pkg/lapi/zzz_session_test.go`, `pkg/appsec/zzz_session_test.go`.
- Live/none LAPI identity omits HTTP timeout. Path: `pkg/lapi/identity.go`.
- Stream/alone session payload omits HTTP timeout. Path: `pkg/lapi/session.go`.
- AppSec identity omits HTTP timeout. Path: `pkg/appsec/session.go`.
- README documents `HTTPTimeoutSeconds` as LAPI-only. Path: `README.md`.
- No hanging-listener AppSec test that would fail if Query still used the 10s default after an AppSec override. Path: not found.

## Desired
- Keep `HTTPTimeoutSeconds` (default 10). Do not rename it.
- Add inheriting second knobs: `LapiHttpTimeoutSeconds` / `lapiHttpTimeoutSeconds`, `AppsecHttpTimeoutSeconds` / `appsecHttpTimeoutSeconds`, `BouncerCaptchaHttpTimeoutSeconds` / `bouncerCaptchaHttpTimeoutSeconds`. Zero or omitted inherits `HTTPTimeoutSeconds`.
- Wire existing clients only: LAPI transport Timeout from EffectiveLapi; AppSec from EffectiveAppsec; captcha siteverify client from EffectiveCaptcha. No second HTTP stack.
- `AdoptTransport` still last-writes a timeout-only reload on the same Client. Timeout stays out of reclaim identity / `IdentityHex` / `Key`. Timeout-only YAML must Adopt, not Open a new Client.
- README documents the three knobs. Example: `appsecHttpTimeoutSeconds: 1` with `bouncerAppsecFailureAction: passthrough`.
- Tests that fail if wiring still reads raw `HTTPTimeoutSeconds`: LAPI Timeout honors the LAPI override (extend session/adopt); AppSec Query against a hanging listener with override 1s + passthrough returns well under 10s; bouncer captcha siteverify Timeout honors the captcha override; omit/0 inherit 10; identity hex unchanged when only timeout knobs differ.

## Affected
- `pkg/configuration` public fields + inherit helpers + `validateParamsRequired` (new knobs may be 0)
- `pkg/lapi/client_http.go` `newTransport` / `AdoptTransport`
- `pkg/appsec/client_http.go` `newTransport` / `AdoptTransport`
- `pkg/bouncer/bouncer.go` captcha `http.Client` Timeout
- `README.md`
- Session/adopt tests, AppSec Query hang test, bouncer captcha Timeout test, inherit + identity-hex tests

## Out of scope
- backendbackoff (separate `2026-09-18-backendbackoff-lapi-appsec` / PR #102)
- `cache.Set`
- captcha gate cookie
- Range
- module path
- HTML-path deprecations
- Putting timeout back into reclaim identity
- Reusing closed PR #41 or branch `2026-09-06-upstream-388-split-appsec-timeout`
- Opening upstream PRs

## Unknowns
- Whether a negative inherit knob is invalid or treated as inherit (ticket names only zero or omitted).
- Whether README should reword `HTTPTimeoutSeconds` from “LAPI only” to the shared default now that dest already applies it to AppSec and captcha.

## Tensions
- Owner declined closed PR #41 / `2026-09-06-upstream-388-split-appsec-timeout` because it put effective timeout back into LAPI/AppSec reclaim identity. Dest `#62` / `#64` last-write timeout on `AdoptTransport`. This ticket must keep that dest invariant.
- Official CrowdSec bouncer spec uses separate `lapi_timeout` / `appsec_timeout` defaults of 200ms (`knowledge/research/ext_crowdsec_bouncers_failure-action/notes.md`). Ticket keeps dest default 10 and inherit-from-shared, not the official 200ms defaults.
- README says `HTTPTimeoutSeconds` is LAPI-only; dest already uses it for AppSec and captcha siteverify.
