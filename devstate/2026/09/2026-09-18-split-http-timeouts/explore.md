# Explore

## Concepts

One public `httpTimeoutSeconds` (default 10) is the `http.Client.Timeout` for three existing clients: LAPI `transport` (`pkg/lapi/client_http.go` `newTransport`), AppSec `transport` (`pkg/appsec/client_http.go` `newTransport`), and the captcha siteverify `*http.Client` built in `bouncer.New` (`pkg/bouncer/bouncer.go`). Captcha `Client.New` stores that client; it does not pick a timeout.

```
  Traefik New (per router)
           │
           ├─ reclaim.Open LAPI  ── AdoptTransport last-writes TLS + Timeout
           ├─ reclaim.Open AppSec ── AdoptTransport last-writes TLS + Timeout
           └─ bouncer.New captcha http.Client (per Bouncer, not reclaimed)
```

Dest already last-writes timeout on the same Client (`AdoptTransport` / `fieldsDiffer` includes `httpTimeoutSeconds`). Timeout is omitted from LAPI `streamSession` / live `identity` and AppSec `identity`. Measured: `TestSessionKey_PolicyAndTLSDoNotChangeKey`, `TestOpenStream_TLSOnlyAdoptsTransport`, `TestOpen_TimeoutOnlyAdoptsTransport` pass on this worktree. No hanging-listener AppSec test exists.

Official CrowdSec spec uses separate `lapi_timeout` / `appsec_timeout` defaults of 200ms (`knowledge/research/ext_crowdsec_bouncers_failure-action/`). Ticket keeps dest default 10 and inherit-from-shared. Upstream context only: maxlerebourg/crowdsec-bouncer-traefik-plugin#388. Closed PR #41 put effective timeout back into reclaim identity; dest `#62`/`#64` last-write on Adopt.

Sister reclaim (this `pkg/reclaim`, `std_go_reclaim`, geoblock utilities table, modsecurity `pkg/reclaim` Default): Traefik `New` ctx is the holder. Do not add `sync.Once` or a package-global HTTP client.

```
  YAML                          effective seconds              stored where
  ─────────────────────────────────────────────────────────────────────────
  httpTimeoutSeconds (default 10, <1 invalid)
       │
       ├─ lapiHttpTimeoutSeconds 0/omit → shared
       │         else override  ──────────────► LAPI transport.httpTimeoutSeconds
       ├─ appsecHttpTimeoutSeconds 0/omit → shared
       │         else override  ──────────────► AppSec transport.httpTimeoutSeconds
       └─ bouncerCaptchaHttpTimeoutSeconds 0/omit → shared
                 else override  ──────────────► Bouncer captcha *http.Client.Timeout
```

## Decisions

- Keep public `HTTPTimeoutSeconds` / `httpTimeoutSeconds`. Do not rename it. Add the three inheriting knobs named in the requirement. `CreateConfig` / `configuration.New` leaves those three at 0 (inherit). Shared default stays 10 and stays in `requiredInt1` (`< 1` invalid).
- One inherit helper on `Config` (one job): `EffectiveHTTPTimeoutSeconds(override int64) int64` returns `HTTPTimeoutSeconds` when `override == 0`, else `override`. LAPI / AppSec / captcha call sites pass their knob. Do not ship three `EffectiveLapi` copies. Do not name the helper `EffectiveLapi` (hides that it is seconds).
- Wire existing clients only. `newTransport` (LAPI and AppSec) and the captcha `http.Client` in `bouncer.New` read the effective seconds. No second HTTP stack. Store **effective** seconds on `transport.httpTimeoutSeconds` so `fieldsDiffer` sees a shared-default change when the override is still 0, and does not replace when override 0 and override 10 both mean 10.
- `AdoptTransport` stays last-write on the same Client. Two routers that share a LAPI or AppSec Client and disagree on that backend’s timeout: last `New` wins (same as TLS today). Captcha is per-Bouncer; each router keeps its own siteverify client.
- Timeout stays out of reclaim identity. Reuse the existing owners; do not add knobs or effective seconds to those payloads. Timeout-only YAML must Adopt, not Open. Do not reuse PR #41 / `2026-09-06-upstream-388-split-appsec-timeout`.
- README rewords `HTTPTimeoutSeconds` from “LAPI only” to the shared default (LAPI, AppSec, captcha siteverify) and documents the three knobs. Example: `appsecHttpTimeoutSeconds: 1` with `bouncerAppsecFailureAction: passthrough`.
- Tests that fail if wiring still reads raw `HTTPTimeoutSeconds`: LAPI adopt with LAPI override; AppSec `Query` against a hanging listener with AppSec override 1s + passthrough returns well under 10s; bouncer captcha siteverify Timeout honors the captcha override; omit/0 inherit 10; identity hex / SessionKey / AppSec Key unchanged when only timeout knobs differ.
- Bound: no backendbackoff, `cache.Set`, captcha gate cookie, Range, module path, or HTML-path deprecations. No `sync.Once` / package-global client. No official 200ms defaults.
- Usage packets already say last `New` AdoptTransport and timeout-out-of-identity. Do not write Language for unimplemented knobs. After apply, update usage on `core_plugin_lapi_connection`, `core_plugin_appsec`, `core_plugin_middleware_config-validation`, and captcha construct (Bouncer, not `Validate`). Propose folds into existing leaves (`core_plugin_lapi_connection`, `core_plugin_appsec_client`, `core_plugin_lapi_reclaim-key`, `core_plugin_middleware_config-validation`); FindSpecHost at propose.

## Open questions

- Q: Who already owns LAPI / AppSec reclaim identity (and must this change set or reconstruct it)?
  Decision: resolved — LAPI stream/alone identity is `pkg/lapi/session.go` (`streamSession` / `SessionHex` / `SessionKey`). LAPI live/none identity is `pkg/lapi/identity.go` (`identity` / `IdentityHex` / `Key`). AppSec identity is `pkg/appsec/session.go` (`identity` / `IdentityHex` / `Key`). Reuse those outputs. Do not add timeout knobs or effective seconds. Client address is not in this ticket; when a path mentions it, reuse `pkg/ip.GetRemoteIP`.
  By: explore

- Q: Whether a negative inherit knob is invalid or treated as inherit (ticket names only zero or omitted).
  Decision: assumed — invalid. New knobs join `requiredInt0` (`cannot be less than 0`). Zero or omitted inherits. The inherit helper inherits only on `override == 0`; it does not coerce negative to shared. `HTTPTimeoutSeconds` stays `< 1` invalid.
  By: explore

- Q: Whether README should reword `HTTPTimeoutSeconds` from “LAPI only” to the shared default now that dest already applies it to AppSec and captcha.
  Decision: resolved — reword to the shared default and document the three knobs plus the AppSec 1s + passthrough example.
  By: explore

- Q: What Go names for the inherit helpers (ticket shorthand `EffectiveLapi` / `EffectiveAppsec` / `EffectiveCaptcha` hides that they return seconds)?
  Decision: assumed — one `Config.EffectiveHTTPTimeoutSeconds(override int64) int64`. Call sites pass `LapiHttpTimeoutSeconds`, `AppsecHttpTimeoutSeconds`, or `BouncerCaptchaHttpTimeoutSeconds`. Do not add three vague `EffectiveLapi` wrappers.
  By: explore

- Q: Official CrowdSec `lapi_timeout` / `appsec_timeout` default 200ms vs dest default 10 and inherit-from-shared.
  Decision: resolved — keep dest default 10 and inherit-from-shared. Do not adopt 200ms. Official fields stay research context (`ext_crowdsec_bouncers_failure-action`).
  By: explore

- Q: Two routers share one LAPI or AppSec Client and set different backend timeouts — per-router Timeout or last-write?
  Decision: resolved — last `New` `AdoptTransport` wins on that Client (dest TLS/timeout invariant). Do not Open a sibling Client. Do not put timeout in the reclaim key to isolate routers. Captcha stays per-Bouncer.
  By: explore

- Q: Should captcha siteverify Timeout live on a reclaimed client (like LAPI/AppSec) so a timeout-only YAML Adopt-s?
  Decision: resolved — no. Captcha `*http.Client` stays constructed on Bouncer. Each `New` already gets a new Bouncer. Do not invent captcha reclaim or `AdoptTransport` for siteverify.
  By: explore

- Q: Should this change reuse closed PR #41 / branch `2026-09-06-upstream-388-split-appsec-timeout`?
  Decision: resolved — no. That approach put effective timeout back into LAPI/AppSec reclaim identity. Dest last-writes timeout on `AdoptTransport`.
  By: explore
