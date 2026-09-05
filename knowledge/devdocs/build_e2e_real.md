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
- `tests/e2e/real/*.Tests.ps1`
- `.github/workflows/e2e.yml`

## Gotchas

- Compose bind-mounts the **repository root** into Traefik’s local plugin path (`../../..` from this folder).
- AppSec cases need Crowdsec `appsec-crs-inband` and `acquis.yaml` on 7422; first boot downloads CRS.
- The test LAPI key `40796d93c2958f9e58345514e67740e5` is a fixture, not a production secret.
