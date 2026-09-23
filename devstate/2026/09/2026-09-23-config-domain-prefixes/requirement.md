# Config domain prefixes

Source for a change proposal. Flat keys, no nesting, no old-key aliases. Each public key starts with the piece that reads it: `lapi`, `appsec`, or `bouncer`. The `crowdsec` syllable goes away. `httpTimeoutSeconds` is removed.

Date: 2026-09-23.

## Boundary

The prefix is the operator's label. It lives on `configuration.Config` (Go field and JSON tag) and nowhere past the package that owns the value.

```
YAML  lapiHost
        │
        ▼
configuration.Config.LapiHost          prefix stays
        │
        ▼
pkg/lapi  identity.Host, client scheme field     prefix drops
pkg/appsec identity.Host                          already dropped
pkg/bouncer  enabled, startupBlock, siteKey arg   prefix drops
pkg/captcha  siteKey, secretKey                   already local
```

Inside a package, the name is the role in that package. `pkg/lapi` does not call its host `LapiHost`. `pkg/appsec` already uses `Scheme`, `Host`, `Path`, `Key`. LAPI identity, ownership, and session match that. `pkg/captcha` already takes `siteKey` and `secretKey`. The bouncer passes `config.BouncerCaptchaSiteKey` into that parameter. It does not grow a `bouncer` field.

A name that distinguishes two legs stays, because that package's scope contains both. On `Bouncer`, `lapiFailureAction` and `appsecFailureAction` stay. The config keys that feed them are `bouncerLapiFailureAction` and `bouncerAppsecFailureAction`. The `bouncer` prefix stops at the struct literal in `bouncer.New`. The `lapi` / `appsec` words stay as the leg.

Protocol constants stay. `X-Api-Key`, `v1/decisions`, CAPI `machine_id`. Those are CrowdSec's names, not this plugin's settings.

Reclaim identity JSON is in-process. Dropping a redundant `lapi` prefix there changes the hash. A process restart builds a new client. That is the same break as the public rename.

`GetVariable(config, "LapiKey")` looks up the Go field `LapiKeyFile`. The string is the new Config field name, not the old one.

## Timeouts

`httpTimeoutSeconds` and `EffectiveHTTPTimeoutSeconds` are deleted. Nothing inherits.

| Key | Default | Who stores it |
| --- | --- | --- |
| `lapiHttpTimeoutSeconds` | 10 | LAPI transport and the LAPI ownership key. Must be >= 1. |
| `appsecHttpTimeoutSeconds` | 10 | AppSec transport and the AppSec ownership key. Must be >= 1. |
| `bouncerCaptchaSiteverifyHttpTimeoutSeconds` | 10 | The per-bouncer captcha `http.Client`. Must be >= 1. |

An omitted AppSec scheme or key still copies from LAPI when AppSec is owned. The timeout does not copy. Setting one timeout does not move the other. An operator who had `httpTimeoutSeconds: 2` and left the overrides at 0 sets both new knobs to 2.

## Unchanged

`logLevel`, `logFormat`, `logFilePath`, and `reclaimGraceSeconds` stay at the root. Logging and process grace are not a leg. `reclaimGraceSeconds` stays process-global, first `New` wins.

## `lapi*`

The client that opens. A subscriber sets `lapiInstanceName` and leaves `lapiEnabled` false.

| Old | New |
| --- | --- |
| `crowdsecLapiEnabled` | `lapiEnabled` |
| `crowdsecLapiInstanceName` | `lapiInstanceName` |
| `crowdsecMode` | `lapiMode` |
| `crowdsecLapiScheme` | `lapiScheme` |
| `crowdsecLapiHost` | `lapiHost` |
| `crowdsecLapiPath` | `lapiPath` |
| `crowdsecLapiKey` | `lapiKey` |
| `crowdsecLapiKeyFile` | `lapiKeyFile` |
| `crowdsecLapiTlsInsecureVerify` | `lapiTlsInsecureVerify` |
| `crowdsecLapiTlsCertificateAuthority` | `lapiTlsCertificateAuthority` |
| `crowdsecLapiTlsCertificateAuthorityFile` | `lapiTlsCertificateAuthorityFile` |
| `crowdsecLapiTlsCertificateBouncer` | `lapiTlsClientCertificate` |
| `crowdsecLapiTlsCertificateBouncerFile` | `lapiTlsClientCertificateFile` |
| `crowdsecLapiTlsCertificateBouncerKey` | `lapiTlsClientKey` |
| `crowdsecLapiTlsCertificateBouncerKeyFile` | `lapiTlsClientKeyFile` |
| `crowdsecLapiHttpTimeoutSeconds` | `lapiHttpTimeoutSeconds` |
| `crowdsecLapiStreamScopes` | `lapiStreamScopes` |
| `updateIntervalSeconds` | `lapiUpdateIntervalSeconds` |
| `metricsUpdateIntervalSeconds` | `lapiMetricsUpdateIntervalSeconds` |
| `updateMaxFailure` | `lapiUpdateMaxFailure` |
| `defaultDecisionSeconds` | `lapiDefaultDecisionSeconds` |
| `crowdsecCapiMachineId` | `lapiCapiMachineId` |
| `crowdsecCapiMachineIdFile` | `lapiCapiMachineIdFile` |
| `crowdsecCapiPassword` | `lapiCapiPassword` |
| `crowdsecCapiPasswordFile` | `lapiCapiPasswordFile` |
| `crowdsecCapiScenarios` | `lapiCapiScenarios` |
| `redisCacheEnabled` | `lapiRedisEnabled` |
| `redisCacheHost` | `lapiRedisHost` |
| `redisCacheReadHosts` | `lapiRedisReadHosts` |
| `redisCachePassword` | `lapiRedisPassword` |
| `redisCachePasswordFile` | `lapiRedisPasswordFile` |
| `redisCacheDatabase` | `lapiRedisDatabase` |

`lapiTlsClientCertificate` is the client cert this process presents to LAPI. The old `CertificateBouncer` spelling collided with the bouncer prefix.

Inside `pkg/lapi` the same values drop the domain word:

| Config field | Inside `pkg/lapi` |
| --- | --- |
| `LapiScheme`, `LapiHost`, `LapiPath`, `LapiKey` | `Scheme`, `Host`, `Path`, `Key` on identity, ownership, and session |
| `LapiTlsClientCertificate`, `LapiTlsClientKey` | `TLSClientCertificate`, `TLSClientKey` |
| `LapiRedisEnabled`, `LapiRedisHost`, `LapiRedisReadHosts`, `LapiRedisPassword`, `LapiRedisDatabase` | `Enabled`, `Host`, `ReadHosts`, `Password`, `Database` on the Redis `storeParams` |
| `LapiCapiScenarios` | `CapiScenarios` |
| `LapiHTTPTimeoutSeconds` | `HTTPTimeoutSeconds` on the transport and the ownership payload |
| `LapiUpdateIntervalSeconds`, `LapiUpdateMaxFailure`, `LapiDefaultDecisionSeconds`, `LapiMode`, `LapiStreamScopes` | `UpdateIntervalSeconds`, `UpdateMaxFailure`, `DefaultDecisionSeconds`, `Mode`, `StreamScopes` |

`lapiDefaultDecisionSeconds` is in the LAPI store identity. `bouncer.New` still copies it onto `Bouncer.defaultDecisionSeconds` and passes that into `LiveLookup`. The parameter name stays `defaultDecisionSeconds`. This rename does not move that call.

## `appsec*`

The listener that opens. Same shape as LAPI.

| Old | New |
| --- | --- |
| `crowdsecAppsecEnabled` | `appsecEnabled` |
| `crowdsecAppsecInstanceName` | `appsecInstanceName` |
| `crowdsecAppsecScheme` | `appsecScheme` |
| `crowdsecAppsecHost` | `appsecHost` |
| `crowdsecAppsecPath` | `appsecPath` |
| `crowdsecAppsecKey` | `appsecKey` |
| `crowdsecAppsecKeyFile` | `appsecKeyFile` |
| `crowdsecAppsecTlsInsecureVerify` | `appsecTlsInsecureVerify` |
| `crowdsecAppsecTlsCertificateAuthority` | `appsecTlsCertificateAuthority` |
| `crowdsecAppsecTlsCertificateAuthorityFile` | `appsecTlsCertificateAuthorityFile` |
| `crowdsecAppsecTlsCertificateBouncer` | `appsecTlsClientCertificate` |
| `crowdsecAppsecTlsCertificateBouncerFile` | `appsecTlsClientCertificateFile` |
| `crowdsecAppsecTlsCertificateBouncerKey` | `appsecTlsClientKey` |
| `crowdsecAppsecTlsCertificateBouncerKeyFile` | `appsecTlsClientKeyFile` |
| `crowdsecAppsecBodyLimit` | `appsecBodyLimit` |
| `crowdsecAppsecHttpTimeoutSeconds` | `appsecHttpTimeoutSeconds` |

Inside `pkg/appsec`, identity already uses `Scheme`, `Host`, `Path`, `Key`, `BodyLimit`, `HTTPTimeoutSeconds`. Rename `TLSCertificateBouncer` / `TLSCertificateBouncerKey` to `TLSClientCertificate` / `TLSClientKey`, including the transport fields that are still spelled `appsecTLSCertificateBouncer`. The transport type is already the AppSec transport.

## `bouncer*`

This router. Failure actions, startup block, and the Redis unreachable block move here because the bouncer reads them. The connection settings they used to sit beside stay on `lapi*` / `appsec*`.

| Old | New |
| --- | --- |
| `enabled` | `bouncerEnabled` |
| `crowdsecLapiFailureAction` | `bouncerLapiFailureAction` |
| `crowdsecAppsecFailureAction` | `bouncerAppsecFailureAction` |
| `streamStartupBlock` | `bouncerStartupBlock` |
| `redisCacheUnreachableBlock` | `bouncerRedisUnreachableBlock` |
| `remediationStatusCode` | `bouncerRemediationStatusCode` |
| `banFilePath` | `bouncerBanFilePath` |
| `captchaFilePath` | `bouncerCaptchaFilePath` |
| `crowdsecDecisionHeader` | `bouncerDecisionHeader` |
| `decisionScopeHeaders` | `bouncerDecisionScopeHeaders` |
| `remediationHeadersCustomName` | `bouncerRemediationHeadersCustomName` |
| `traceHeadersCustomName` | `bouncerTraceHeadersCustomName` |
| `forwardedHeadersCustomName` | `bouncerForwardedHeadersCustomName` |
| `forwardedHeadersInsecure` | `bouncerForwardedHeadersInsecure` |
| `forwardedHeadersTrustedIps` | `bouncerForwardedHeadersTrustedIps` |
| `clientTrustedIps` | `bouncerClientTrustedIps` |
| `originBasedDecisionRemap` | `bouncerOriginBasedDecisionRemap` |
| `captchaProvider` | `bouncerCaptchaProvider` |
| `captchaCustomJsUrl` | `bouncerCaptchaCustomJsUrl` |
| `captchaCustomValidateUrl` | `bouncerCaptchaCustomValidateUrl` |
| `captchaCustomKey` | `bouncerCaptchaCustomKey` |
| `captchaCustomResponse` | `bouncerCaptchaCustomResponse` |
| `captchaCustomChallengeUrl` | `bouncerCaptchaCustomChallengeUrl` |
| `captchaCustomValidateBody` | `bouncerCaptchaCustomValidateBody` |
| `captchaSiteKey` | `bouncerCaptchaSiteKey` |
| `captchaSiteKeyFile` | `bouncerCaptchaSiteKeyFile` |
| `captchaSecretKey` | `bouncerCaptchaSecretKey` |
| `captchaSecretKeyFile` | `bouncerCaptchaSecretKeyFile` |
| `captchaGateSecret` | `bouncerCaptchaGateSecret` |
| `captchaGateSecretFile` | `bouncerCaptchaGateSecretFile` |
| `captchaGateBindIp` | `bouncerCaptchaGateBindIp` |
| `captchaGracePeriodSeconds` | `bouncerCaptchaGracePeriodSeconds` |
| `captchaSiteverifyHttpTimeoutSeconds` | `bouncerCaptchaSiteverifyHttpTimeoutSeconds` |

Inside `pkg/bouncer` the existing local names stay, with two renames that follow the public key:

| Config field | On `Bouncer` |
| --- | --- |
| `BouncerEnabled` | `enabled` |
| `BouncerLapiFailureAction` | `lapiFailureAction` |
| `BouncerAppsecFailureAction` | `appsecFailureAction` |
| `BouncerStartupBlock` | `startupBlock` (today `streamStartupBlock`) |
| `BouncerRedisUnreachableBlock` | `redisUnreachableBlock` |
| `BouncerDecisionHeader` | `forcedDecisionHeader` |
| `LapiInstanceName` / `AppsecInstanceName` | `lapiInstanceName` / `appsecInstanceName` |
| `BouncerCaptcha*` | arguments to `captcha.Client`, which already uses `siteKey`, `secretKey`, `gateSecret` |

`bouncerStartupBlock` drops "stream" because the flag gates every subscribed leg, LAPI and AppSec.

## Removed

| Old | New |
| --- | --- |
| `httpTimeoutSeconds` | — |

## What moves with the public names

README, `examples/`, `.traefik.yml` `testData`, tests, `knowledge/devdocs/`, and the OpenSpec specs that name a public key. Validation errors name the new Go field (`LapiHTTPTimeoutSeconds`, `cannot be less than 1`).

A subscriber file after the rename:

```yaml
cs-admin:
  plugin:
    bouncer:
      lapiInstanceName: shared
      appsecInstanceName: shared
      bouncerEnabled: true
      bouncerRemediationHeadersCustomName: x-crowdsec
```

## Current (code)

- Public `Config` JSON tags still use `crowdsec*` / unprefixed names (`enabled`, `httpTimeoutSeconds`, `crowdsecLapiHost`, `redisCacheEnabled`, `captchaSiteKey`, `streamStartupBlock`): `pkg/configuration/configuration.go`
- `HTTPTimeoutSeconds` defaults to 10; per-leg knobs default 0 and inherit via `EffectiveHTTPTimeoutSeconds`: `pkg/configuration/configuration.go`
- Shared timeout is `requiredInt1` (`< 1` invalid); `CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, `CaptchaSiteverifyHTTPTimeoutSeconds` are `requiredInt0` (`< 0` invalid): `pkg/configuration/configuration.go`
- `GetVariable` looks up `key + "File"` then `key` on `Config`; call sites pass old names (`CrowdsecLapiKey`, `CrowdsecLapiTLSCertificateBouncer`, `CrowdsecAppsecKey`, `CaptchaSiteKey`): `pkg/configuration/configuration.go`
- LAPI identity / ownership still carry `LapiScheme`, `LapiHost`, `LapiPath`, `LapiKey`, `TLSCertificateBouncer`, `CrowdsecCapiScenarios`: `pkg/lapi/identity.go`
- LAPI transport stores `lapiTLSCertificateBouncer` and effective timeout from `EffectiveHTTPTimeoutSeconds(CrowdsecLapiHTTPTimeoutSeconds)`: `pkg/lapi/client_http.go`
- LAPI Redis `storeParams` still uses `RedisCacheEnabled`, `RedisCacheHost`, `RedisCacheReadHosts`, `RedisCachePassword`, `RedisCacheDatabase`: `pkg/lapi/decisionstore.go`
- AppSec identity already uses `Scheme`, `Host`, `Path`, `Key`; still `TLSCertificateBouncer` / `TLSCertificateBouncerKey`: `pkg/appsec/session.go`
- AppSec transport still spells `appsecTLSCertificateBouncer`: `pkg/appsec/client_http.go`
- Omitted AppSec scheme or key copies from LAPI in `Prepare`; timeout is not copied there: `pkg/appsec/client.go`
- `Bouncer` already has `enabled`, `lapiFailureAction`, `appsecFailureAction`, `streamStartupBlock`, `redisUnreachableBlock`, `forcedDecisionHeader`, `lapiInstanceName`, `appsecInstanceName`: `pkg/bouncer/bouncer.go`
- Captcha siteverify `http.Client` timeout is `EffectiveHTTPTimeoutSeconds(CaptchaSiteverifyHTTPTimeoutSeconds)`: `pkg/bouncer/bouncer.go`
- Captcha client already takes local `siteKey` / `secretKey`: `pkg/captcha` (not found as `bouncer` fields)
- `.traefik.yml` `testData` still `Enabled` / `CrowdsecLapiKey`: `.traefik.yml`
- Operator docs still name old keys: `README.md`
- Examples still name old keys: `examples/`
- Mock e2e dynamics still `crowdsecLapiHost`: `tests/e2e/mock/scenarios/`
- Real e2e still `crowdsecLapiHost` and `httpTimeoutSeconds`: `tests/e2e/real/config/dynamic/dynamic-scopes.yml`
- Live spec still requires `HTTPTimeoutSeconds` plus inherit knobs: `openspec/specs/core_plugin_middleware_config-validation/spec.md`
- Live LAPI / AppSec / bouncer specs still name `EffectiveHTTPTimeoutSeconds` and old public keys: `openspec/specs/core_plugin_lapi_connection/spec.md`, `openspec/specs/core_plugin_appsec_client/spec.md`, `openspec/specs/core_plugin_middleware_bouncer/spec.md`
- Usage docs still describe inherit timeouts and old keys: `knowledge/devdocs/core_plugin_middleware_config-validation.md`, `knowledge/devdocs/core_plugin_lapi_connection.md`, `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/build_e2e_real.md`
- Named design file is not on dest or this worktree: `docs/config-domain-prefixes.md` not found

## Out of scope

- Old-key aliases or nested YAML (the design forbids both)
- Renaming CrowdSec protocol constants (`X-Api-Key`, `v1/decisions`, CAPI `machine_id`)
- Moving `defaultDecisionSeconds` off `Bouncer` / `LiveLookup`
- Copying AppSec TLS material from LAPI
- Changing reclaim table mechanics beyond the identity JSON field names the design names
- Vendor or Traefik-core changes

## Unknowns

- Full inventory of every README, example, test, spec, and usage leaf that names a public key (explore)
- Unmeasured runtime of the identity JSON rename (the design treats it as a process restart; not measured here)
- Whether `CreateConfig` / Yaegi only expose JSON tags, or other string surfaces still name old fields
- Operator files that set `httpTimeoutSeconds: 2` and leave per-leg overrides at 0 (the design says set both new knobs to 2; no alias)
- Whether every `GetVariable` and validation error string site is listed above

## Tensions

- Live `core_plugin_middleware_config-validation` SHALL keep `HTTPTimeoutSeconds` and inherit via `EffectiveHTTPTimeoutSeconds`; this design deletes both
- Per-leg overrides today allow `0` (inherit) and reject `< 0`; the design requires each new knob `>= 1` and nothing inherits
- LAPI identity still prefixes `Lapi*`; AppSec already dropped that prefix; the design asks LAPI to match AppSec
- `GetVariable` call sites pass `Crowdsec*` field names; the design says the string is the new Config field (`LapiKey`)
- `.traefik.yml`, README, examples, and e2e still use old keys; the design ships no aliases
