# Real-stack e2e (Docker Traefik + Crowdsec, Pester)

This suite boots **Traefik, Crowdsec, and Dragonfly** in Docker, loads the plugin as a
local Traefik plugin, and asserts remediations against a live LAPI. Dragonfly is
the functional Redis-protocol cache for `redis_cache.Tests.ps1`.

It is a different domain from [`../mock/`](../mock/) (Traefik binary + mock
LAPI) and from [`../go/`](../go/) (`go test -tags realredis` against Dragonfly
with no Traefik). Do not mix the three trees.

Harness shape is the author’s [PR 273](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/273)
(PowerShell + Pester). Cases that 273 did not have come from
[PR 333](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/333)
as Pester, not bash: live mode, trusted IPs, custom ban page, real AppSec CRS.

Country matching on `/scope-none` and `/scope-stream` chains [traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) in enrich mode, then the bouncer. `Test-Integration.ps1` clones geoblock `v1.2.0` into `config/.geoblock/` (gitignored) before `docker compose up`. Nested plugin maps live in `config/dynamic/dynamic-scopes.yml`. Instance-severance reloads write `config/dynamic/instance-severance.yml`. Fixtures and compose live under `config/`.

```bash
./tests/e2e/real/Test-Integration.ps1
# or from the repo root
make e2e_pester
```
