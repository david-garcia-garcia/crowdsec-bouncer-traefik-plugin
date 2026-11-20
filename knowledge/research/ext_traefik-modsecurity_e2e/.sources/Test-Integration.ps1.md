---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/Test-Integration.ps1
title: Test-Integration.ps1
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:Test-Integration.ps1
---

SYNOPSIS: Runs integration tests for the Traefik ModSecurity Plugin. Two stacks (Apache and nginx CRS, inspect-only sidecar): apache-drain → docker-compose.test.yml; nginx-drain → docker-compose.test.nginx.yml.

Parameters: SkipDockerCleanup, SkipWait, TestPath default `./scripts/*.Tests.ps1`, ComposeFile default `./docker-compose.test.yml`, Stack ValidateSet apache-drain|nginx-drain, AllStacks, PesterFullNameFilter, PesterTagFilter.

Get-IntegrationStackComposeFiles: apache-drain → @('./docker-compose.test.yml'); nginx-drain → @('./docker-compose.test.nginx.yml').

Wait-ForAllServices URLs: http://localhost:8080/api/rawdata (Traefik API), http://localhost:8000/bypass, http://localhost:8000/protected.

Invoke-IntegrationStack sets `$env:INTEGRATION_STACK = $StackName`, compose up -d, Pester Detailed, compose down -v unless SkipDockerCleanup.

Main: AllStacks and Stack mutually exclusive. AllStacks runs apache-drain then nginx-drain. Else if Stack, that one. Else ComposeFile and infers stack name from filename (nginx → nginx-drain, else apache-drain).
