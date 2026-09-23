## Why

Public Config keys still mix `crowdsec*` syllables, unprefixed router knobs, and one inheriting `httpTimeoutSeconds`. Operators cannot tell which piece reads a key, and a leftover shared timeout silently moves LAPI, AppSec, and captcha. Flat domain prefixes (`lapi`, `appsec`, `bouncer`) make the owner visible and delete inherit.

## What Changes

- Rename every public `Config` JSON tag and Go field so the key starts with the piece that reads it: `lapi*`, `appsec*`, or `bouncer*`. Drop the `crowdsec` syllable. Logging and `reclaimGraceSeconds` stay at the root.
- **BREAKING**: no old-key aliases and no nested YAML. Operator files, `.traefik.yml` `testData`, README, examples, and e2e must use the new names. `GetVariable` strings are the new Go field names (`LapiKey`, `LapiTLSClientCertificate`).
- **BREAKING**: delete `httpTimeoutSeconds` and `EffectiveHTTPTimeoutSeconds`. Three independent knobs default to 10 and MUST be `>= 1`: `lapiHttpTimeoutSeconds`, `appsecHttpTimeoutSeconds`, `bouncerCaptchaSiteverifyHttpTimeoutSeconds`. Nothing inherits. An omitted AppSec scheme or key still copies from LAPI when AppSec is owned; the timeout does not copy.
- Drop the domain prefix at the package that owns the value. `pkg/lapi` identity, ownership, and session match AppSec (`Scheme`, `Host`, `Path`, `Key`). Rename `TLSCertificateBouncer` → `TLSClientCertificate` / `TLSClientKey` on both legs. Redis `storeParams` and CAPI fields drop the public `lapi`/`crowdsec` syllables inside `pkg/lapi`. `pkg/captcha` stays local (`siteKey`, `secretKey`).
- On `Bouncer`, keep distinguishing names (`lapiFailureAction`, `appsecFailureAction`). Rename `streamStartupBlock` → `startupBlock` (the flag gates every subscribed leg). Public keys are `bouncerLapiFailureAction`, `bouncerAppsecFailureAction`, `bouncerStartupBlock`.
- Reclaim identity JSON reuses `pkg/lapi/identity.go` and `pkg/appsec/session.go` marshalers. Do not reconstruct the payload in `configuration` or `bouncer`. Field-name change is a hash change: a process restart builds a new client (same break as the public rename).
- Fold the eleven live catalog leaves that name a public key. No new spec family. Do not migrate `openspec/changes/archive` or other runs' `devstate`. Do not ship `docs/config-domain-prefixes.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: public field and JSON names; three independent timeout knobs `>= 1`; REMOVED inherit timeout / `EffectiveHTTPTimeoutSeconds`; `GetVariable` and error strings use new Go field names.
- `core_plugin_middleware_bouncer`: public keys on the snapshot and request path (`bouncerEnabled`, `bouncerStartupBlock`, `bouncerDecisionHeader`, captcha siteverify timeout is `BouncerCaptchaSiteverifyHTTPTimeoutSeconds`); `streamStartupBlock` field → `startupBlock`.
- `core_plugin_lapi_connection`: LAPI transport timeout is `LapiHTTPTimeoutSeconds` (no inherit helper); timeout change Opens a new Client (ownership key includes the knob).
- `core_plugin_lapi_reclaim-key`: ownership and SessionHex field names; reuse `identity.go` marshalers; LAPI JSON drops redundant `lapi` prefix; TLS/Redis/CAPI JSON names; timeout stays on the ownership key and out of SessionHex.
- `core_plugin_lapi_scope-union`: opener list is `lapiStreamScopes`; subscriber map is `bouncerDecisionScopeHeaders`.
- `core_plugin_lapi_failure-action`: public fallback is `bouncerLapiFailureAction`; stream unhealthy counter is `lapiUpdateMaxFailure`; mode is `lapiMode`.
- `core_plugin_appsec_client`: public listener keys; AppSec timeout is `AppsecHTTPTimeoutSeconds`; reuse `session.go` marshaler; TLS client-cert names; scheme/key copy from `lapi*` when AppSec is owned (timeout does not copy).
- `core_plugin_appsec_failure-action`: public fallback is `bouncerAppsecFailureAction`.
- `core_plugin_appsec_bot-detection`: enable flag is `appsecEnabled`; failure-action and status-code public names.
- `core_plugin_decisionstore_store`: public Redis and interval keys in scenarios (`lapiRedis*`, `lapiUpdateIntervalSeconds`); `bouncerStartupBlock` stays off the store key.
- `build_e2e_pester_crowdsec-stack`: compose, labels, and file-provider YAML use the new public keys; real e2e `httpTimeoutSeconds: 60` becomes both new knobs set to 60.

## Impact

- `pkg/configuration` (fields, JSON tags, defaults, `ValidateParams`, `GetVariable` call sites and prefix helpers; delete `EffectiveHTTPTimeoutSeconds` and `HTTPTimeoutSeconds`).
- `plugin.go` comments; `.traefik.yml` `testData`.
- `pkg/lapi` (`identity.go` marshalers, `client.go`, `client_http.go`, `decisionstore.go` `storeParams`).
- `pkg/appsec` (`session.go` marshaler, `client.go`, `client_http.go` TLS field names).
- `pkg/bouncer` (`startupBlock`, captcha siteverify timeout, `GetVariable` strings). `pkg/captcha` is not renamed.
- README, `examples/**` plugin files, `tests/e2e/mock` and `tests/e2e/real` plugin YAML, unit tests that name old fields.
- Live catalog deltas in this change folder. Usage packets move with implement / `opd-devdocsimpact` (Language deltas already shown in explore).
- **BREAKING** for every operator file that still uses `crowdsec*`, unprefixed router knobs, or `httpTimeoutSeconds`.
