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
- On Windows, when `docker info` OSType is not `linux`, the runner selects context `Desktop-Linux` and re-checks. It does not fail closed if the switch fails.
- Bounce routes share one `whoami` (`whoami-test`). Add a router + middleware on that service and set `traefik.http.routers.<name>.service=whoami`. Do not add another whoami container.
- Keep new cases as `tests/e2e/real/*.Tests.ps1`. Put compose and fixtures in `tests/e2e/real/config/`. Do not put cases in `tests/e2e/mock/` or at `tests/` root.
- Identify the client only with `X-Forwarded-For`. Do not parse `RemoteAddr`.
- Custom-ban and captcha compose labels set `banFilePath` / `captchaFilePath`. Do not use `banHtmlFilePath` / `captchaHtmlFilePath` or HTML-cased twins.
- Nested plugin maps (`decisionScopeHeaders`, geoblock `databaseSources`) MUST use the file provider (`tests/e2e/real/config/dynamic/dynamic-scopes.yml`). Docker labels do not decode those maps.
- Instance-severance reload cases overwrite `tests/e2e/real/config/dynamic/instance-severance.yml` in the watched directory. Keep a real idle router on disk (`sev-idle`). Empty `http: {}` is ignored and leaves the previous routers. After a host write, `docker exec traefik-test touch` the same path so Traefik’s inotify fires on Windows bind mounts, then wait for the exact `sev-*@file` set. Compose mounts `./dynamic` read-write with `--providers.file.watch=true`. Probe the route; do not sleep-only.
- Traefik e2e logs are `--log.format=json` and `--log.nocolor=true`. Plugin labels and file-provider YAML set `logFormat: json`. Do not assert text stems such as `leg=appsec`.
- Real-stack compose and file-provider YAML set `reclaimGraceSeconds: 2` so reclaim dispose is not the production 30s. Instance-severance R2/R5 wait 3s, not 40.
- Every LAPI-owning compose label and mock YAML must set `crowdsecLapiEnabled: true`. AppSec-only is `false` plus `crowdsecAppsecEnabled: true` (`/waf-only`, mock `appsec`).
- Country matching uses traefik-geoblock enrich on a **public** `X-Forwarded-For`. Do not inject a client-set country header for that case.
- CI runs this suite as two jobs, `e2e (docker + pester / lapi)` and `e2e (docker + pester / appsec)`, from `tests/e2e/real/PesterDomains.ps1`. Each job boots its own stack. `make e2e_pester` still runs every file. `e2e (binary + mock LAPI)` stays the mock job; `e2e (go + dragonfly)` is DecisionStore `go test` against Dragonfly (`build_e2e_go-redis.md`).

## Pattern snippet

```powershell
./tests/e2e/real/Test-Integration.ps1
# one file
./tests/e2e/real/Test-Integration.ps1 -TestPath "./tests/e2e/real/mode_live.Tests.ps1"
```

## Key files

- `tests/e2e/real/Test-Integration.ps1`
- `tests/e2e/real/config/docker-compose.test.yml`
- `tests/e2e/real/config/dynamic/dynamic-scopes.yml`
- `tests/e2e/real/instance_severance.Tests.ps1`
- `tests/e2e/real/*.Tests.ps1`
- `.github/workflows/e2e.yml`

## Gotchas

- Compose bind-mounts the **repository root** into Traefik’s local plugin path (`../../../..` from `tests/e2e/real/config`).
- Windows Docker Desktop in Windows-container mode: the runner runs `docker context use Desktop-Linux`. A machine without that context still fails at compose.
- Redis-cache cases need Dragonfly (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`) on the compose network as `dragonfly:6379`.
- Do not put a second Redis route under `PathPrefix(`/redis-cache`)` (for example `/redis-cache-hold`). Traefik can apply the short-TTL middleware to that path; the restart proof uses `/hold-redis`.
- Redis cache keys are the client IP. A long-TTL restart case MUST use a different `X-Forwarded-For` than a short-TTL case, or a cache hit will keep the 2s key and never `SET EX 120`.
- AppSec cases need Crowdsec `appsec-crs-inband` and `acquis.yaml` on 7422; first boot downloads CRS.
- Usage-metrics cases (`usage_metrics.Tests.ps1`) need `metricsUpdateIntervalSeconds=10` on `/stream`, `/trusted`, and `/appsec`. Default 600s would miss CI. `/stream` and `/trusted` MUST NOT share a LAPI key: two stream owners with the same host and key both `New`, but CrowdSec has one stream cursor per hashed key and this process logs `crowdsec lapi stream collision`. Each stream middleware POSTs on its own ticker.
- Bot-detection cases need Crowdsec `v1.8.0`, collection `crowdsecurity/appsec-bot-challenge`, `acquis.d` on 7423, and a Traefik `PathPrefix(/crowdsec-internal/challenge)` through the same AppSec middleware. A stale `crowdsec-config-test` volume from 1.7.8 can hide the new acquisition — recreate the volume after the image bump.
- The test LAPI key `40796d93c2958f9e58345514e67740e5` is a fixture, not a production secret. Pester talks to LAPI with that key. Compose reuses it only on middlewares whose SessionHex already differs (none `/whoami`, stream `/stream`, live `/live`, none `/lapi-fail-ban` on `crowdsec:9`, appsec `/waf-only`). Every other Traefik name that would share mode+host registers its own `BOUNCER_KEY_*`. Isolation is a second bouncer API key, not a second middleware name.
- The file-provider stream bouncer uses `BOUNCER_KEY_TRAEFIK_SCOPES`. Do not share one LAPI stream key with the docker-label `/stream` middleware: polls race the CrowdSec cursor (`crowdsec lapi stream collision`). Isolation is a second bouncer API key.
- Captcha solve uses `captchaProvider: custom` and compose service `dummy-captcha` (`POST /siteverify` always `{"success":true}`). Pester POSTs `dummy-captcha-response` and asserts `crowdsec_captcha_gate`. Do not call hCaptcha/Turnstile.
- Traefik drops unused keys. An old-key-only `banHtmlFilePath` / `captchaHtmlFilePath` label serves CreateConfig defaults, not the suite HTML.
- Extra coverage routes (`/header-none`, `/lapi-fail-*`, `/waf-only`, `/waf-fail-*`, `/status-429`, `/short-captcha`) share the same `whoami` origin. Do not put them under `PathPrefix(/appsec)` or `PathPrefix(/captcha)`.
- Username/AS/Country placeholder cases use `/header-none` (file-provider `decisionScopeHeaders`, no geoblock). Do not inject `CF-IPCountry` on `/scope-none` — geoblock overwrites `X-IPCountry`.
- CrowdSec `type=allow` over a ban is not in this suite. The Pester file and the storage follow-up live in `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`.
- LAPI/AppSec failure-action routes point at `crowdsec:9` with `httpTimeoutSeconds=2`. Do not `docker pause` Crowdsec; that would stall the shared LAPI.
- Docker labels for `CrowdsecLapiHost` are `crowdseclapihost`. `crowdseclapishost` (extra `s`) does not match; Traefik drops it and CreateConfig keeps `crowdsec:8080`.
- Compose IPAM is `172.28.0.0/16` (gateway `172.28.0.1`) so docker-label `forwardedHeadersTrustedIPs` can pin that gateway without colliding with a common `172.20.0.0/16` on the same Docker engine. File-provider routes still trust `172.16.0.0/12`.
