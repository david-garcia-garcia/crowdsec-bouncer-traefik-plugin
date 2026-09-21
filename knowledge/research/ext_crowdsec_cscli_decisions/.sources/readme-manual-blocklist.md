---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87/README.md
title: README.md — Manually add an IP to the blocklist
fetched: 2026-09-05
authority: source
ref: this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:README.md
---

docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m -t captcha
docker exec crowdsec cscli decisions remove --ip 10.0.0.10 -t captcha
Uses remove; official docs document delete (v1.7.8 cobra alias).
