# Real-stack e2e (Docker Traefik + Crowdsec, Pester)

This suite boots **Traefik and Crowdsec in Docker**, loads the plugin as a
local Traefik plugin, and asserts remediations against a live LAPI.

It is a different domain from [`../mock/`](../mock/) (Traefik binary + mock
LAPI). Do not mix the two trees.

```bash
./tests/e2e/real/Test-Integration.ps1
# or from the repo root
make e2e_pester
```
