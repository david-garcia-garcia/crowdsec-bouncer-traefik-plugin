---
url: file://tests/e2e/real/README.md
title: tests/e2e/real/README.md (this product)
fetched: 2026-10-12
authority: source
ref: crowdsec-bouncer-traefik-plugin worktree tests/e2e/real/README.md
---

This product’s real-stack e2e boots Traefik, Crowdsec, and Dragonfly in Docker, loads the plugin as a local Traefik plugin, and asserts remediations against a live LAPI. Harness: tests/e2e/real/Test-Integration.ps1 + config/docker-compose.test.yml + *.Tests.ps1. Distinct from tests/e2e/mock and tests/e2e/go. Fixtures and compose live under config/.
