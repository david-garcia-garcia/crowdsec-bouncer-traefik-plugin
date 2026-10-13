# GitHub Actions GOPATH

## Overview

Main and race GitHub Actions jobs check out this repo at `go/src/` plus the Go module path so Yaegi and `go test` resolve the same import as `go.mod`. Identity owner: `core_plugin_middleware_local-plugin.md`. Specs: `build_ci_github_module-path`, `build_ci_github_race-detector`.

## How to use

- Check out at `go/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`.
- Set `defaults.run.working-directory` to that path.
- Point Yaegi `GOPATH` at `${{ github.workspace }}/go`.
- Before `yaegi test`, copy vendored `traefik-middleware-utilities` to `$GOPATH/src/github.com/david-garcia-garcia/traefik-middleware-utilities`. Yaegi v0.16 does not load that test-only import from `vendor/`.
- Do not check out at `github.com/${{ github.repository }}`.
- Keep the race job on the same path. Do not race the module-root package.

## Pattern snippet

```yaml
defaults:
  run:
    working-directory: ${{ github.workspace }}/go/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
steps:
  - uses: actions/checkout@v7
    with:
      path: go/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
```

## Key files

- `.github/workflows/main.yml`
- `go.mod`

## Gotchas

- Yaegi loads `pkg/` from `GOPATH/src/<Go module path>`. A checkout that follows `github.repository` instead of `go.mod` fails with “unable to find source related to” on a fork.
- Root-package tests that import `traefik-middleware-utilities/traefikemulator` need that module on `$GOPATH/src`, not only under this repo’s `vendor/`. Production reclaim still resolves through `pkg/reclaim` plus vendor.
