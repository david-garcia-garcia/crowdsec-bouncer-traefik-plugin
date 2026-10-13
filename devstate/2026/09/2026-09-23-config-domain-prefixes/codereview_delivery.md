# Delivery

## Motivation

Traefik binds operator YAML and labels onto `configuration.Config` through JSON tags. Those tags are the public contract. Three pieces read that struct: the LAPI client, the AppSec listener, and the bouncer.

The tags mix `crowdsec*` (`crowdsecLapiHost`, `crowdsecMode`, `crowdsecLapiTlsCertificateBouncer`), unprefixed router knobs (`enabled`, `captchaSiteKey`, `updateIntervalSeconds`, `redisCacheEnabled`), and one shared `httpTimeoutSeconds`. `enabled` bounces; `crowdsecLapiEnabled` owns the client — the prefix does not say which piece reads the key. Redis connection knobs sit beside `redisCacheUnreachableBlock`, which the bouncer reads. `CertificateBouncer` collides with the bouncer syllable.

An operator who sets `httpTimeoutSeconds: 2` and leaves `crowdsecLapiHttpTimeoutSeconds`, `crowdsecAppsecHttpTimeoutSeconds`, and `captchaSiteverifyHttpTimeoutSeconds` at 0 silently moves all three HTTP clients. The inherit helper treats zero as “use the shared default.”

Left alone, every new knob keeps the mix. Operators keep guessing ownership. A leftover shared timeout keeps coupling three clients that should be independent.

Priority: P2 — real operator pain with a workaround or limited blast radius

## Implementation

Rename every public `Config` JSON tag and matching Go field so the key starts with the piece that reads it (`lapi*`, `appsec*`, `bouncer*`). Drop the `crowdsec` syllable. `logLevel`, `logFormat`, `logFilePath`, and `reclaimGraceSeconds` stay at the root. No old-key aliases and no nested YAML.

The prefix stays on `configuration.Config` and drops at the owning package. `pkg/lapi` identity, ownership, and session now use `scheme` / `host` / `path` / `key`, matching AppSec. Both legs rename `tlsCertificateBouncer` to `tlsClientCertificate` / `tlsClientKey`. `bouncer.New` keeps local names (`enabled`, `lapiFailureAction`, `startupBlock`) and passes `BouncerCaptcha*` into the existing captcha `siteKey` / `secretKey` arguments. `GetVariable` strings are the new Go field names (`LapiKey`, `LapiTLSClientCertificate`); TLS helpers become `Lapi` / `Appsec` plus `TLSCertificateAuthority` / `TLSClientCertificate` / `TLSClientKey`.

Delete `httpTimeoutSeconds` and `EffectiveHTTPTimeoutSeconds`. Each client reads its own knob, default 10, must be `>= 1`: `lapiHttpTimeoutSeconds`, `appsecHttpTimeoutSeconds`, `bouncerCaptchaSiteverifyHttpTimeoutSeconds`. An omitted AppSec scheme or key still copies from LAPI when AppSec is owned; the timeout does not. Validation errors name the new fields.

Reclaim identity JSON reuses the existing LAPI and AppSec marshalers. Dropping the redundant `lapi` prefix and renaming the TLS fields changes the hash; a process restart builds a new client, the same break as the public rename.

README, examples, compose labels, `.traefik.yml` testData, mock and real e2e, and the change-folder specs ship the new names in the same apply.

## What this changes

**Operators.** Rewrite every plugin YAML key and Traefik label to `lapi*` / `appsec*` / `bouncer*`; old names are ignored and `bouncerEnabled` defaults false. A shared `httpTimeoutSeconds: N` becomes `lapiHttpTimeoutSeconds: N` and `appsecHttpTimeoutSeconds: N` (captcha siteverify is `bouncerCaptchaSiteverifyHttpTimeoutSeconds`, default 10).

**Admin users.** None.

**Developers.** `configuration.Config` fields and JSON tags are the new names; `GetVariable` takes those Go field names; `EffectiveHTTPTimeoutSeconds` is deleted; LAPI identity, ownership, and session drop the `lapi` prefix to match AppSec.

**End users.** None.
