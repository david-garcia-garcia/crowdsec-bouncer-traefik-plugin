---
url: https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/v1.9.6
title: Catalog download HTTP status (measured)
fetched: 2026-11-15
authority: inference
---

2026-11-15:

GET https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/v1.8.2 → 500
GET https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/v1.9.0 → 200
GET https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/v1.9.1 … v1.9.5 → 200
GET https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/v1.9.6 → 200 application/zip (4673061 bytes)
GET https://plugins.traefik.io/public/download/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/v1.8.1 → 200
GET https://plugins.traefik.io/api/services/plugins?query=david-garcia-garcia → name github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin, latestVersion v1.9.6, createdAt 2026-09-21T08:02:30.521Z
GET https://api.github.com/repos/david-garcia-garcia/crowdsec-bouncer-traefik-plugin → "fork": false

2026-09-18 (superseded, before the catalog listed this module):

GET https://plugins.traefik.io/public/download/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/v1.7.1 → 200
GET https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/v1.7.1 → 404
GET https://plugins.traefik.io/public/download/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/vX.Y.Z → 404

URL shape from Traefik pluginsURL + download/{module}/{version}. Status only; response bodies not stored.
