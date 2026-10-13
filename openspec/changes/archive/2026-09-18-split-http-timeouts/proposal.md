## Why

One public `httpTimeoutSeconds` (default 10) is the `http.Client.Timeout` for LAPI, AppSec, and captcha siteverify. An AppSec hang waits the same duration as a LAPI stream GET. Operators need inheriting per-backend knobs without putting timeout back into reclaim identity (declined PR #41).

## What Changes

- Keep `HTTPTimeoutSeconds` / `httpTimeoutSeconds` (default 10, `< 1` invalid). Do not rename it.
- Add three inheriting knobs: `CrowdsecLapiHTTPTimeoutSeconds` / `crowdsecLapiHttpTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds` / `crowdsecAppsecHttpTimeoutSeconds`, `CaptchaSiteverifyHTTPTimeoutSeconds` / `captchaSiteverifyHttpTimeoutSeconds`. Zero or omitted inherits. Negative is invalid (`requiredInt0`).
- One `Config.EffectiveHTTPTimeoutSeconds(override int64)` owner. Call sites pass their knob. Do not ship three `EffectiveLapi` copies.
- Wire existing clients only: LAPI and AppSec `newTransport` and the captcha `http.Client` in `bouncer.New`. Store **effective** seconds on transport so `AdoptTransport` last-writes. Timeout stays out of reclaim identity / `IdentityHex` / `Key`.
- README rewords `HTTPTimeoutSeconds` to the shared default and documents the three knobs. Example: `crowdsecAppsecHttpTimeoutSeconds: 1` with `crowdsecAppsecFailureAction: passthrough`.
- No **BREAKING** public JSON/YAML keys. Shared default stays 10 (not official CrowdSec 200ms).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: three inheriting timeout knobs; one `EffectiveHTTPTimeoutSeconds`; new knobs join `requiredInt0`; shared `HTTPTimeoutSeconds` stays `< 1` invalid.
- `core_plugin_lapi_connection`: LAPI `newTransport` Timeout and stored `httpTimeoutSeconds` are the effective LAPI seconds; `AdoptTransport` last-writes.
- `core_plugin_appsec_client`: AppSec `newTransport` Timeout and stored seconds are the effective AppSec seconds; Query against a hang honors the AppSec override; AppSec `Key` still omits timeout knobs.
- `core_plugin_lapi_reclaim-key`: the three new knobs stay out of stream `SessionKey` / live `Key` / `IdentityHex` (reuse existing identity owners).
- `core_plugin_middleware_bouncer`: captcha siteverify `http.Client` Timeout is the effective captcha seconds; no captcha reclaim.

## Impact

- `pkg/configuration` (fields, inherit helper, `validateParamsRequired`)
- `pkg/lapi/client_http.go` `newTransport` / `AdoptTransport`
- `pkg/appsec/client_http.go` `newTransport` / `AdoptTransport` and a Query hang test
- `pkg/bouncer/bouncer.go` captcha `http.Client` Timeout
- `README.md`
- Session/adopt tests, identity-hex tests, bouncer captcha Timeout test
- Usage packets after apply (`core_plugin_lapi_connection`, `core_plugin_appsec`, `core_plugin_middleware_config-validation`, captcha construct). Not this change folder.
