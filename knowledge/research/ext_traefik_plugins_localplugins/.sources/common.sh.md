---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87/tests/e2e/mock/lib/common.sh
title: tests/e2e/mock/lib/common.sh
fetched: 2026-09-05
authority: source
ref: this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:tests/e2e/mock/lib/common.sh
---

TRAEFIK_VERSION default v3.7.11 (downloaded binary, not Docker).
Comment: unlike the Docker suite, this one replaces Crowdsec with mocklapi.
Expose plugin source where Traefik localPlugins expects it:
mkdir plugins-local/src/github.com/maxlerebourg
ln -s "$REPO_ROOT" .../crowdsec-bouncer-traefik-plugin
WORKDIR is a temp dir used as Traefik process CWD.
