---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87/docker-compose.yml
title: docker-compose.yml
fetched: 2026-09-05
authority: source
ref: this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.yml
---

Comment: We need to register one api key per service we will use.
BOUNCER_KEY_TRAEFIK: FIXME-LAPI-KEY-1=
crowdseclapikey=FIXME-LAPI-KEY-1=
crowdsec image crowdsecurity/crowdsec:v1.7.8
COLLECTIONS same traefik + appsec collections.
Volume crowdsec-db:/var/lib/crowdsec/data/
