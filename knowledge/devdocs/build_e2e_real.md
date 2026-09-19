# Real-stack e2e

## Language

**Real-stack e2e**:
The Pester suite that boots Docker Traefik and a live Crowdsec, loads this plugin as a local Traefik plugin, and asserts remediations against that LAPI.
_Avoid_: mock e2e, binary e2e, `tests/e2e/scenarios`

**Mock e2e**:
The bash suite under `tests/e2e/mock/` that runs Traefik as a binary and replaces Crowdsec with `mocklapi`.
_Avoid_: real-stack, Docker e2e

## Overview

Use this suite when the check must include Traefik’s plugin loader and a real Crowdsec (cscli decisions, stream/live, AppSec CRS). Keep mock e2e for fast plugin-only CI.

## How to use

- Run `./tests/e2e/real/Test-Integration.ps1` or `make e2e_pester` from the repo root.
- Keep new cases as `tests/e2e/real/*.Tests.ps1`. Do not put them in `tests/e2e/mock/` or at `tests/` root.
- Identify the client only with `X-Forwarded-For`. Do not parse `RemoteAddr`.
- Custom-ban and captcha compose labels set `banFilePath` / `captchaFilePath`. Do not use `banHtmlFilePath` / `captchaHtmlFilePath` or HTML-cased twins.
- Nested plugin maps (`decisionScopeHeaders`, geoblock `databaseSources`) MUST use the file provider (`tests/e2e/real/dynamic-scopes.yml`). Docker labels do not decode those maps.
- Country matching uses traefik-geoblock enrich on a **public** `X-Forwarded-For`. Do not inject a client-set country header for that case.
- CI job `e2e (docker + pester)` runs this suite; `e2e (binary + mock LAPI)` stays the mock job.

## Pattern snippet

```powershell
./tests/e2e/real/Test-Integration.ps1
# one file
./tests/e2e/real/Test-Integration.ps1 -TestPath "./tests/e2e/real/mode_live.Tests.ps1"
```

## Key files

- `tests/e2e/real/Test-Integration.ps1`
- `tests/e2e/real/docker-compose.test.yml`
- `tests/e2e/real/dynamic-scopes.yml`
- `tests/e2e/real/*.Tests.ps1`
- `.github/workflows/e2e.yml`

## Gotchas

- Compose bind-mounts the **repository root** into Traefik’s local plugin path (`../../..` from this folder).
- Redis-cache cases need Dragonfly (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`) on the compose network as `dragonfly:6379`.
- Do not put a second Redis route under `PathPrefix(`/redis-cache`)` (for example `/redis-cache-hold`). Traefik can apply the short-TTL middleware to that path; the restart proof uses `/hold-redis`.
- Redis cache keys are the client IP. A long-TTL restart case MUST use a different `X-Forwarded-For` than a short-TTL case, or a cache hit will keep the 2s key and never `SET EX 120`.
- AppSec cases need Crowdsec `appsec-crs-inband` and `acquis.yaml` on 7422; first boot downloads CRS.
- Usage-metrics cases (`usage_metrics.Tests.ps1`) need `metricsUpdateIntervalSeconds=1` on every docker-label stream middleware that shares the fixture LAPI key (`/stream` and `/trusted`) and on `/appsec`. Default 600s would miss CI. Stream interval is silent first-wins on the shared cursor-plus-Redis Client: if `/trusted` omitted the label, a first `New` on that router would keep a 600s ticker. Matching `=1` is so the shared ticker POSTs within 20s, not a uniqueness workaround. The file-provider stream bouncer still uses a second fixture key (`BOUNCER_KEY_TRAEFIK_SCOPES`) so `scopes=` isolation is a different CrowdSec bouncer row.
- Bot-detection cases need Crowdsec `v1.8.0`, collection `crowdsecurity/appsec-bot-challenge`, `acquis.d` on 7423, and a Traefik `PathPrefix(/crowdsec-internal/challenge)` through the same AppSec middleware. A stale `crowdsec-config-test` volume from 1.7.8 can hide the new acquisition — recreate the volume after the image bump.
- The test LAPI key `40796d93c2958f9e58345514e67740e5` is a fixture, not a production secret.
- The file-provider stream bouncer uses a second fixture key (`BOUNCER_KEY_TRAEFIK_SCOPES`). Do not share one LAPI stream key with the docker-label `/stream` middleware or the polls race.
- Captcha solve uses `captchaProvider: custom` and compose service `dummy-captcha` (`POST /siteverify` always `{"success":true}`). Pester POSTs `dummy-captcha-response` and asserts `crowdsec_captcha_gate`. Do not call hCaptcha/Turnstile.
- Traefik drops unused keys. An old-key-only `banHtmlFilePath` / `captchaHtmlFilePath` label serves CreateConfig defaults, not the suite HTML.
- Extra coverage routes live on the `coverage` whoami (`/header-none`, `/lapi-fail-*`, `/waf-only`, `/waf-fail-*`, `/status-429`, `/short-captcha`). Do not put them under `PathPrefix(/appsec)` or `PathPrefix(/captcha)`.
- Username/AS/Country placeholder cases use `/header-none` (file-provider `decisionScopeHeaders`, no geoblock). Do not inject `CF-IPCountry` on `/scope-none` — geoblock overwrites `X-IPCountry`.
- CrowdSec `type=allow` over a ban is not in this suite. The Pester file and the storage follow-up live in `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`.
- LAPI/AppSec failure-action routes point at `crowdsec:9` with `httpTimeoutSeconds=2`. Do not `docker pause` Crowdsec; that would stall the shared LAPI.
- Docker labels for `CrowdsecLapiHost` are `crowdseclapihost`. `crowdseclapishost` (extra `s`) does not match; Traefik drops it and CreateConfig keeps `crowdsec:8080`.
- Compose IPAM is `172.28.0.0/16` (gateway `172.28.0.1`) so docker-label `forwardedHeadersTrustedIPs` can pin that gateway without colliding with a common `172.20.0.0/16` on the same Docker engine. File-provider routes still trust `172.16.0.0/12`.
