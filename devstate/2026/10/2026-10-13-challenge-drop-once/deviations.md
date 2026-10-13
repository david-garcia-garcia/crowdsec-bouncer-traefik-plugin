# Deviations

- [x] taken  skip only the request dropped counter dest already posts
  Asked: a relay under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes).
  Instead: skip `blockedRequests` only; do not add a bytes series.
  Owner: `bouncer.go` `reportMetrics`
  Why: dest's metrics POST has a single `dropped` request item and no bytes series; adding bytes would change the POST shape, which the ask forbids.
  By: explore
  Requester: not asked

- [x] taken  symlink GOPATH module path so Yaegi finds pkg/cache on this fork
  Asked: CI on the PR head succeeds.
  Instead: map `$GOPATH/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` to the fork checkout; do not change go.mod.
  Owner: `.github/workflows/main.yml`
  Why: dest `main` already failed Main Process at `yaegi test` with `unable to find source related to pkg/cache` because checkout uses `github.repository` while go.mod is still maxlerebourg. Lint and e2e were already green.
  By: pullrequest
  Requester: not asked
