# Example: CrowdSec Country decisions via geoenrich

This plugin does not geolocate. Country (and AS) matching reads a **request header** that some other hop already set: a CDN, a reverse proxy, or another Traefik middleware.

This example chains [traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) in `mode: enrich` **before** the CrowdSec bouncer. Geoblock looks up the client IP in a local GeoIP database and writes `X-IPCountry`. The bouncer maps CrowdSec scope `Country` to that header.

```
client → Traefik → geoblock (enrich) → crowdsec-bouncer → whoami
```

Geoblock must not block here. CrowdSec owns the Country ban. Use a public client IP: RFC1918 addresses enrich as `PRIVATE`, which this bouncer skips (not ISO 3166-1 alpha-2).

Nested maps (`decisionScopeHeaders`, geoblock `databaseSources`) live in [`dynamic.yml`](dynamic.yml). Docker labels do not decode those maps reliably.

## Run

From the repository root (clones geoblock `v1.2.0` into `examples/geoenrich-decisions/geoblock` if missing):

```bash
make run_geoenrich
```

Or:

```bash
git clone --depth 1 --branch v1.2.0 https://github.com/david-garcia-garcia/traefik-geoblock.git examples/geoenrich-decisions/geoblock
docker compose -f examples/geoenrich-decisions/docker-compose.yml up -d
```

The compose file loads **this tree** as a local Traefik plugin so `decisionScopeHeaders` works before it is in a catalog release. Geoblock is also local (`useunsafe` is required). Switch both to catalog plugins after a bouncer release that includes this key; keep geoblock `settings.useunsafe=true`.

Traefik 3.5+ is required for geoblock.

## Try it

Probe a public IP and read the country geoblock wrote (whoami echoes request headers):

```bash
curl -s -H "X-Forwarded-For: 8.8.8.8" http://localhost:8000/foo
```

Look for `X-Ipcountry: US` (or whatever the seed DB returns for that address). Ban that country in CrowdSec:

```bash
docker exec crowdsec cscli decisions add --scope Country --value US -d 1h --type ban
```

The same public IP is then forbidden:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 8.8.8.8" http://localhost:8000/foo
# 403
```

A private IP is still allowed (geoblock writes `PRIVATE`; the bouncer skips Country):

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 10.0.0.20" http://localhost:8000/foo
# 200
```

Delete the decision when done:

```bash
docker exec crowdsec cscli decisions delete --scope Country --value US
```

## Configuration that matters

In [`dynamic.yml`](dynamic.yml):

- Geoblock `mode: enrich`, `allowPrivate: true`, seed BIN from the cloned plugin (no download token).
- Bouncer `decisionScopeHeaders.Country: X-IPCountry`.
- Chain `geo-enrich` then `crowdsec` on the router (`crowdsec-geo@file`).

Client IP identity stays `X-Forwarded-For`. The entrypoint trusts Docker/LAN CIDRs so that header is not client-spoofable from outside those networks.

See the plugin README `decisionScopeHeaders` section for Country/AS normalize rules (`XX`/`T1` do not match).
