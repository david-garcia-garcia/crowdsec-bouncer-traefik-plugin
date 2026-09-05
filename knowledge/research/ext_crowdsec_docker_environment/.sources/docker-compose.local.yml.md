---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87/docker-compose.local.yml
title: docker-compose.local.yml
fetched: 2026-09-05
authority: source
ref: this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.local.yml
---

crowdsec image crowdsecurity/crowdsec:v1.7.8
COLLECTIONS: crowdsecurity/traefik crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
BOUNCER_KEY_TRAEFIK: 40796d93c2958f9e58345514e67740e5=
middleware crowdseclapikey matches that key.
Volume crowdsec-db-local:/var/lib/crowdsec/data/
No DISABLE_ONLINE_API. No CROWDSEC_BYPASS_DB_VOLUME_CHECK.
