# Mock LAPI e2e

## Language

**Mock e2e**:
The bash suite under `tests/e2e/mock/` that runs Traefik as a binary and replaces Crowdsec with `mocklapi`.
_Avoid_: real-stack, Docker e2e, Pester

**dual-bouncer**:
The mock scenario that loads two bouncer middlewares against two mock LAPIs in one Traefik process.
_Avoid_: two Traefik containers, real Crowdsec

## Overview

Use this suite for plugin-only CI and for proving two Crowdsec configs in one process. Keep real-stack Pester for Traefik’s plugin loader plus a live Crowdsec.

## How to use

- Add a folder under `tests/e2e/mock/scenarios/<name>/`.
- Captcha scenarios set `captchaEnabled: true` and `captchaFilePath`. Do not use `captchaHtmlFilePath` or leftover `bouncerCaptcha*`. A set `captchaProvider` alone does not own captcha.
- dual-bouncer: two middlewares, two LAPI ports (`LAPI_PORT_B`), `lapi_add_decision_at`.
- Header-mapped scopes: `tests/e2e/mock/scenarios/scope-headers/` injects synthetic Country/AS/username headers. Real-stack Country uses geoblock instead.
- `mocklapi --lapi-only` when AppSec is not under test.
- The mocklapi AppSec stand-in picks its verdict from `X-Crowdsec-Appsec-Uri`: `rpc2` / `403` block, `challenge` relays a challenge envelope, `appsec-captcha` answers `{"action":"captcha","http_status":403}` on GET only (the captcha form POST is allowed, as a GET-keyed rule would), `appsec-tarpit` answers an unknown bodyless action, `500` / `502` exercise the failure action. Name a probe path after the verdict you need; do not reuse one of those words by accident.
- CI job `e2e (binary + mock LAPI)` runs this suite.

## Pattern snippet

```bash
make e2e_mock
# or one scenario via the mock harness
```

## Key files

- `tests/e2e/mock/scenarios/dual-bouncer/`
- `tests/e2e/mock/scenarios/scope-headers/`
- `tests/e2e/mock/scenarios/captcha/`
- `tests/e2e/mock/scenarios/appsec-captcha/`
- `tests/e2e/mock/lib/common.sh`
- `.github/workflows/e2e.yml`

## Gotchas

- Identify the client with `X-Forwarded-For`. Do not parse `RemoteAddr`.
- Two LAPIs must disagree on a decision so a cache leak would fail the scenario.
- Captcha solve uses `captchaProvider: custom` and mocklapi `POST /siteverify` (`{"success":true}`). POST `dummy-captcha-response`; do not call a real provider. The gate cookie is `crowdsec_captcha_gate`.
- Traefik drops unused keys. An old-key-only `captchaHtmlFilePath` serves CreateConfig `/captcha.html`, not the scenario file.
