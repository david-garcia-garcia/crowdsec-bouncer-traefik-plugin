---
url: https://github.com/crowdsecurity/crowdsec/blob/632274597a88a6b01ed41c0e6affca0f87ff26df/build/docker/docker_start.sh
title: build/docker/docker_start.sh cscli wrapper (v1.7.8)
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:build/docker/docker_start.sh
---

cscli() { command cscli -c "$CONFIG_FILE" "$@"; }
CONFIG_FILE default /etc/crowdsec/config.yaml
docker exec into the running container uses this cscli against the container LAPI.
