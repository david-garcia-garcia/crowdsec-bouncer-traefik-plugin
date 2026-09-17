---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87/examples/trusted-ips/README.md
title: examples/trusted-ips/README.md
fetched: 2026-09-05
authority: source
ref: this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:examples/trusted-ips/README.md
---

docker exec crowdsec cscli decisions add --ip 10.0.10.30 -d 10m
Expect 403 on http://localhost/foo after the ban.
