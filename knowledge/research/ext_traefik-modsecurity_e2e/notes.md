# Real e2e inventory

Inventory of the real Docker + Pester suite in [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) at `e860d2494f41d49172f2d8aae916615c8ee356e1`, for later port into this product’s `tests/e2e/real` Pester stack (`Test-Integration.ps1` + `config/docker-compose.test.yml` + `*.Tests.ps1`).

Fetched: 2026-10-12.

## Runner and stacks

`Test-Integration.ps1` (repo root) starts compose, waits, runs Pester on `./scripts/*.Tests.ps1` (default), then `docker compose down -v` unless `-SkipDockerCleanup`. Prerequisites named in README Testing: Docker, Docker Compose, PowerShell 7+. Owner: `github.com/david-garcia-garcia/traefik-modsecurity@e860d249:Test-Integration.ps1`; [README Testing](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md). Extracts: `.sources/Test-Integration.ps1.md`, `.sources/README-testing.md`.

Two named inspect-only CRS stacks (`ValidateSet`):

| Stack | Compose file | Default? |
| --- | --- | --- |
| `apache-drain` | `./docker-compose.test.yml` | yes (`-ComposeFile` default; `./Test-Integration.ps1` with no `-Stack`) |
| `nginx-drain` | `./docker-compose.test.nginx.yml` | `-Stack nginx-drain` or `-ComposeFile ./docker-compose.test.nginx.yml` |

`-AllStacks` runs both in sequence (compose down between). `-Stack` and `-AllStacks` are mutually exclusive. Owner: `…@e860d249:Test-Integration.ps1` (`Get-IntegrationStackComposeFiles`, comment block). Extract: `.sources/Test-Integration.ps1.md`.

The runner sets `$env:INTEGRATION_STACK` to the stack name for bombardier bench lines. Readiness GETs: `http://localhost:8080/api/rawdata`, `http://localhost:8000/bypass`, `http://localhost:8000/protected` (skipped when Pester filters are set). Owner: same file (`Wait-ForAllServices`, `Invoke-IntegrationStack`).

## Compose files (shared shape)

Both test compose files: Traefik `traefik:v3.7.12` ports **8080** (API) and **8000** (HTTP), JSON access log keeping `X-Waf-Status`, `experimental.localPlugins.traefik-modsecurity.moduleName=github.com/david-garcia-garcia/traefik-modsecurity`, bind-mount of the repo as the local plugin, file provider `./test-dynamic`, `entrypoints.web.http.sanitizePath=false`. Owner: `…@e860d249:docker-compose.test.yml`, `…@e860d249:docker-compose.test.nginx.yml`. Extracts: `.sources/docker-compose.test.yml.md`, `.sources/docker-compose.test.nginx.yml.md`.

WAF image pin `owasp/modsecurity-crs:4.3.0-{apache|nginx}-alpine-202406090906`, inspect-only overlays:

- Apache: `crs-apache/httpd-vhosts.drain.conf` → `httpd-vhosts.conf`; `REMOTEIP_HEADER=X-Real-IP`, `REMOTEIP_INT_PROXY` RFC1918 list. Owner: `docker-compose.test.yml`.
- nginx: `crs-nginx/realip.conf`, `drain-origin.conf`, `proxy_backend.drain.conf.template`; `REAL_IP_HEADER=X-Real-IP`, comma-separated `SET_REAL_IP_FROM`, `MODSEC_AUDIT_LOG=/tmp/modsecurity/modsec_audit.log`. Owner: `docker-compose.test.nginx.yml`.

Labeled whoami (and related) routes — same names on both stacks:

| Path prefix | Middleware knobs that differ from a plain WAF |
| --- | --- |
| `/protected` | `waf-middleware`: timeout 3000, `X-Waf-Status`, `maxBodySizeBytes=1024`, `logLevel=debug` |
| `/bypass` | no plugin |
| `/remediation-test` | backoff 5s, `unhealthyWafFailureThreshold=1` |
| `/error-test` | `modSecurityUrl=http://invalid-waf-url:9999`, backoff 5s, threshold 1 |
| `/force-test` | default deny-verbs; `maxBodySizeBytes=1024` |
| `/large-body-test` | `maxBodySizeBytes=20971520`, timeout 30000 |
| `/threshold-test` | backoff 10s, threshold 3, window 30 (window unused by the gate) |
| `/pool-test` | `maxBodySizeBytes=5120`, `maxBodySizeBytesForPool=1024` |
| `/waf-5xx-test` | sidecar `waf-5xx` (nginx fixture 503 `sidecar-5xx-marker`); backoff omitted |
| `/chain-retry` | WAF then Traefik retry |
| `/chain-buffer` | Traefik buffering then WAF |
| `/ws-echo` | `jmalloc/echo-server:v0.3.7` behind `waf-middleware` |
| `/reclaim-a`, `/reclaim-b` | file provider `test-dynamic/reclaim.yml` (not Docker labels) |
| `/retry-force` | file provider `test-dynamic/chain-retry-replay.yml` (dead first LB + whoami) |

Owners: the two compose files; `…@e860d249:test-dynamic/reclaim.yml`; `…@e860d249:test-dynamic/chain-retry-replay.yml`; `…@e860d249:test-fixtures/waf-5xx.conf`. Extracts: compose extracts plus `.sources/test-dynamic.md`, `.sources/waf-5xx.conf.md`.

`docker-compose.yml` / `docker-compose.local.yml` are demo/dev, not the Pester stacks. Owner: README Usage / Local development (not duplicated here).

## Pester files and Describe families

Default `TestPath` is `./scripts/*.Tests.ps1`, so both files below run. Helpers: `scripts/TestHelpers.ps1` (dot-sourced). Owner: `…@e860d249:Test-Integration.ps1`; `…@e860d249:scripts/TestHelpers.ps1`. Extract: `.sources/TestHelpers.ps1.md`.

### `scripts/integration-tests.Tests.ps1`

Describe names (order in file):

1. `ModSecurity Plugin Basic Functionality` — Traefik API, `/bypass`, `/protected`, no CRS dummy origin container.
2. `WAF Protection Tests` — SQLi/XSS/traversal/command probes; audit `REMOTE_ADDR` == Traefik `ClientHost`; audit Host == incoming Host; Range/If-None-Match/If-Modified-Since must not copy sidecar 416/304; POST body CRS; origin-form and absolute-form Request-URI.
3. `Remediation Response Header Tests` — `X-Waf-Status` is a **request** header for access logs (`ok` / blocked path / `unhealthy` after stop / `error` on `/error-test`).
4. `Bypass Functionality Tests` — malicious query on `/bypass` allowed.
5. `Performance and Health Tests` — latency cap, concurrent GETs.
6. `Performance Comparison Tests` — WAF vs bypass averages.
7. `MaxBodySizeBytes Configuration Tests` — `/protected` 1KB limit 413; chunked POST on `/pool-test`.
8. `DenyVerbsWithBody Configuration Tests` — `/force-test` GET/HEAD/DELETE-with-body → 400; POST/PUT allowed.
9. `WAF Health Tracker Threshold Tests` — `/threshold-test` under-threshold still `error`; trip → `unhealthy` fail-open 200; GET-with-body still 400 after trip; inspect resumes after 10s backoff.
10. `Traefik middleware chain with WAF` — `/chain-retry`, `/retry-force`, `/chain-buffer`.
11. `Plugin reclaim logs` (tag `Reclaim`) — file-provider `waf-reclaim` put/dispose.
12. `WebSocket through WAF middleware` — echo two frames on `/ws-echo`; Upgrade does not skip CRS.
13. `Sidecar 5xx is not a copied block` — `/waf-5xx-test` fail-open 200, token `error`, no `sidecar-5xx-marker`.
14. `Error Handling and Edge Cases` — 1KB POST; URL-encoded query.
15. `Allow-path throughput` — bombardier GET/POST on `/protected` (skip if binary missing).

Owner: `…@e860d249:scripts/integration-tests.Tests.ps1`. Extract: `.sources/integration-tests.Tests.ps1.md`.

### `scripts/integration-tests.BodySize.Tests.ps1`

Describe names:

1. `MaxBodySizeBytes Configuration Tests (Large Bodies)` — 16MB near 20MB must not 5xx; 21MB → 413 on `/large-body-test`.
2. `Chunked POST vs pool threshold` — 2KB chunked 200 / 6KB chunked 413 on `/pool-test`.
3. `MaxBodySizeBytes Status Header Tests` — pooled-path 413 logs `blocked`.
4. `Body Size Limit Tests - usePool=false Path` — sizes around 1KB pool / 5KB max; backend not called on 6KB.
5. `Chunked POST vs pool threshold` — **second copy of the same Describe title** (duplicate block in this pin).

Owner: `…@e860d249:scripts/integration-tests.BodySize.Tests.ps1`. Extract: `.sources/integration-tests.BodySize.Tests.ps1.md`.

## Port into this repo’s `tests/e2e/real`

This product already runs Pester from `tests/e2e/real/Test-Integration.ps1` against `config/docker-compose.test.yml` (Traefik + Crowdsec + Dragonfly, local plugin). Owner: this worktree `tests/e2e/real/README.md` (product tree, not the third-party pin). The modsecurity suite is a second compose topology (CRS sidecar + many labeled whoami routes + `scripts/TestHelpers.ps1`). Implement later: add a compose overlay or stack switch for CRS apache-drain/nginx-drain, copy or adapt the Describe families above, keep ports **8000/8080** or remap helpers. Do not mix with `tests/e2e/mock` or `tests/e2e/go`.
