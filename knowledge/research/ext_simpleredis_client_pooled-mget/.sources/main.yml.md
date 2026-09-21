---
url: https://github.com/maxlerebourg/simpleredis/blob/f8801cc098d2ae1743a6f82cb1e60a97e9461b7f/.github/workflows/main.yml
title: .github/workflows/main.yml
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/simpleredis@f8801cc098d2ae1743a6f82cb1e60a97e9461b7f:.github/workflows/main.yml
---

Workflow name Main. Triggers: push to branch main, and pull_request.

Job test on ubuntu-latest: checkout, setup-go from go.mod, gofmt check, go vet ./..., go test -race -count=1 ./...

No Yaegi step. No Traefik step.
