---
url: https://docs.crowdsec.net/u/getting_started/installation/docker
title: Install with Docker or Podman
fetched: 2026-09-05
authority: official
---

Since CrowdSec 1.7.0 it is mandatory to persist /var/lib/crowdsec/data in a volume or the container will refuse to start.
COLLECTIONS: space-separated collections to install.
BOUNCER_KEY_<name>: seed value as API key for remediation under <name>.
Full env list is in the Docker image readme.
Example compose mounts crowdsec-db:/var/lib/crowdsec/data/ and crowdsec-config:/etc/crowdsec/.
