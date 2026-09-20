# Go-layer real Redis e2e

## Language

**Go-layer real Redis e2e**:
`go test` sources tagged `realredis` that dial a live Dragonfly (Redis protocol) instead of the in-process RESP stand-in, asserting DecisionStore behavior below Traefik’s HTTP surface.
_Avoid_: Pester real-stack, mock LAPI e2e, `testStoreRedis`

## Overview

Use this suite when Redis-protocol semantics (MSetEX, EX TTL, prefix isolation, Close) must be true on Dragonfly, not on the unit-test fake. Keep Pester for Traefik plugin-loader and Crowdsec LAPI. Keep untagged `go test` docker-free.

## How to use

- Add cases as `zzz_e2e_*_test.go` next to the package, with `//go:build realredis` on the file.
- Start Dragonfly with `tests/e2e/go/docker-compose.yml` (same image as the Pester `dragonfly` service). Dial `REALREDIS_ADDR` or `127.0.0.1:6379`.
- Run `make test_realredis` from the repo root. Do not add `-tags realredis` to `make test`.
- CI job `e2e (go + dragonfly)` runs this suite; `e2e (docker + pester)` stays the HTTP/Pester job.

## Pattern snippet

```bash
make test_realredis
```

## Key files

- `pkg/decisionstore/zzz_e2e_realredis_test.go`
- `tests/e2e/go/docker-compose.yml`
- `.github/workflows/e2e.yml`

## Gotchas

- The in-process RESP stand-in ignores `SET EX`; TTL expiry only belongs in this tagged suite.
- Each test must use its own Redis key prefix (`t.Name()`) so parallel CI jobs on one Dragonfly do not share slots.
- Do not boot Traefik or Crowdsec for these tests. That stack is `build_e2e_real.md`.
