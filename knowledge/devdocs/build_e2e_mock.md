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
- dual-bouncer: two middlewares, two LAPI ports (`LAPI_PORT_B`), `lapi_add_decision_at`.
- `mocklapi --lapi-only` when AppSec is not under test.
- CI job `e2e (binary + mock LAPI)` runs this suite.

## Pattern snippet

```bash
make e2e_mock
# or one scenario via the mock harness
```

## Key files

- `tests/e2e/mock/scenarios/dual-bouncer/`
- `tests/e2e/mock/common.sh`
- `.github/workflows/e2e.yml`

## Gotchas

- Identify the client with `X-Forwarded-For`. Do not parse `RemoteAddr`.
- Two LAPIs must disagree on a decision so a cache leak would fail the scenario.
