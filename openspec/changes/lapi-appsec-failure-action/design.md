## Context

See proposal.md — Why. After merge with `master`, `AppsecQuery` returns `(*AppsecResponse, error)` and `Bouncer` relays structured challenge/ban/captcha envelopes. Failure vs unreachable vs unreadable body is still three booleans on `AppsecPolicy`. Live LAPI errors still return `BannedValue`. Stream unhealthy cache miss still hard-bans. `UpdateMaxFailure` already lives on CrowdsecConnection identity.

## Goals / Non-Goals

**Goals:**
- One enum per backend, CrowdSec value names, default `ban`.
- Keep `UpdateMaxFailure` as the stream *when*.
- Keep challenge relay and `GetRemoteIP` ownership.

**Non-Goals:**
- Changing `StreamStartupBlock` or `RedisCacheUnreachableBlock`.
- Parsing `__crowdsec_challenge` or a second client IP.
- Matching CrowdSec spec default passthrough.
- Aliasing the three removed AppSec bools.

## Decisions

1. **Values `passthrough` | `ban` | `captcha` as lowercase strings.** Match CrowdSec spec / nginx-ish naming, not a custom fail-open pair. Alternative: `pass`/`block` — rejected; operators reading CrowdSec docs should see the same words.

2. **`AppsecPolicy` holds `FailureAction string` (or a small named type in `pkg/configuration`).** Replace the three bools. `AppsecQuery` maps `ban` to today’s error return, `passthrough` to `appsecAllow()`, `captcha` to a dedicated result the bouncer turns into `pkg/captcha` — not AppSec JSON `action: captcha`. Alternative: return captcha as `AppsecResponse{Action:"captcha"}` — rejected; that envelope is HTML relay, not the LAPI captcha client.

3. **Live lookup: do not return `BannedValue` on transport/HTTP error.** Return a distinguishable miss/error and let ServeHTTP apply `CrowdsecLapiFailureAction`. Alternative: encode the action inside `queryLiveDecisions` — rejected; the connection should classify the LAPI failure, the bouncer applies the action (same split as AppSec).

4. **Stream unhealthy miss stays in `Bouncer.ServeHTTP`.** Replace `handleBanServeHTTP(..., ReasonTECH)` with a helper that switches on `CrowdsecLapiFailureAction`. Cache hits stay above that branch.

5. **Reclaim:** add `CrowdsecLapiFailureAction` to `identity`. Do not add `CrowdsecAppsecFailureAction` to identity. Alternative: both on identity — rejected; explore said two routers may disagree on AppSec fallback.

6. **Validate `captcha` only when `CaptchaProvider` is set.** Same gate as existing captcha config. Alternative: treat missing provider as `ban` at request time — rejected; fail at ValidateParams so Traefik does not start with a silent downgrade.

7. **Remove the three bool fields from `Config`.** Traefik ignores unknown YAML keys. Default `ban` matches old default `true`. Operators with `false` must set `passthrough`. Alternative: `*bool` deprecation window — rejected; extra public surface for one release.

## Risks / Trade-offs

- [Silent ignore of old `false` bools] → README + examples call out **BREAKING**; default stays fail-closed.
- [Captcha vs AppSec captcha HTML] → names in logs/comments must say which owner (`pkg/captcha` vs envelope relay).
- [Yaegi] → keep new types next to existing config/connection types; no new root `New`.

## Migration Plan

Plugin version bump. Operators set the two keys if they do not want default `ban`. Remove the three AppSec bools from compose/README. Rollback: previous tag restores the bools. `UpdateMaxFailure` YAML is unchanged.
