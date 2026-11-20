---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md
title: README Testing
fetched: 2026-10-12
authority: official
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:README.md
---

Integration tests against real Docker services:

- `./Test-Integration.ps1` — Apache CRS (default stack)
- `./Test-Integration.ps1 -Stack nginx-drain` — nginx CRS
- `./Test-Integration.ps1 -AllStacks` — both stacks
- `./Test-Integration.ps1 -SkipDockerCleanup` — keep services running

Prerequisites: Docker, Docker Compose, PowerShell 7+.
