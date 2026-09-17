---
url: https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/build/docker/README.md
title: crowdsec Docker README (v1.7.8)
fetched: 2026-09-05
authority: official
ref: github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:build/docker/README.md
---

Since CrowdSec 1.7.0, /var/lib/crowdsec/data/ must be mounted; otherwise the container refuses to start.
Automatic bouncer registration at startup via env BOUNCER_KEY_<NAME>=<key> (example BOUNCER_KEY_nginx=mysecretkey12345) or Docker secret bouncer_key_<name>.
Cannot update an existing bouncer without deleting it first.
Recommend alphanumeric keys.
DISABLE_ONLINE_API default false: Disable online API registration for signal sharing.
COLLECTIONS: Collections to install, separated by space.
CROWDSEC_BYPASS_DB_VOLUME_CHECK default false: Bypass volume check for /var/lib/crowdsec/data/
cscli binary: /usr/local/bin/cscli
Image flavor crowdsecurity/crowdsec:{version} is the latest stable Alpine image.
