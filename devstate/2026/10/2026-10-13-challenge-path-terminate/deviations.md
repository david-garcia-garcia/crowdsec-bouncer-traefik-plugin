# Deviations

- [x] taken  README-only operator contract instead of updating a spec
  Asked: Update the spec and the README sentence that tells operators the prefix is safe whenever the middleware covers the host.
  Instead: dest `main` has no OpenSpec catalog; document the 404 in README only.
  Owner: `README.md`
  Why: honouring the wording would bootstrap `openspec/` as a new catalog on dest, which has no spec leaves or callers.
  By: explore
  Requester: not asked

- [x] taken  GOPATH symlink so Yaegi finds this fork's module
  Asked: terminate internal challenge paths (plugin 404, README, tests).
  Instead: also map GOPATH to `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` in Main CI.
  Owner: `.github/workflows/main.yml`
  Why: Yaegi looks up GOPATH/src/<go.mod module> while checkout lands under `github.repository`; Main was failing before this plugin change could be measured.
  By: implement
  Requester: not asked
