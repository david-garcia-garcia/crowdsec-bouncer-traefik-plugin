---
url: https://github.com/crowdsecurity/crowdsec/blob/632274597a88a6b01ed41c0e6affca0f87ff26df/build/docker/docker_start.sh
title: build/docker/docker_start.sh (v1.7.8)
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:build/docker/docker_start.sh
---

cscli() wraps command cscli -c "$CONFIG_FILE".
register_bouncer: if name not in cscli bouncers list, cscli bouncers add "$1" -k "$2".
If /var/lib/crowdsec/data is not a mount and CROWDSEC_BYPASS_DB_VOLUME_CHECK is empty, print mandatory-volume message and exit 0.
If DISABLE_ONLINE_API is true: conf_set 'del(.api.server.online_client)'. Else if LAPI enabled, may cscli capi register.
prepare_hub: if COLLECTIONS set, cscli collections install difference(COLLECTIONS, DISABLE_COLLECTIONS).
Env loop: for BOUNCER in $(compgen -A variable | grep -i BOUNCER_KEY); NAME=$(cut -d_ -f3-); register_bouncer "$NAME" "$KEY".
