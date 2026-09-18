## 1. Module identity

- [x] 1.1 Set `go.mod` `module` to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- [x] 1.2 Rewrite every in-tree import of the old module (root + `pkg/**`) and `.golangci.yml` depguard allow list
- [x] 1.3 Set `.traefik.yml` `import` to the same `go.mod` path; keep package clause; do not add `basePkg`
- [x] 1.4 Set `.traefik.yml` `displayName` to `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`

## 2. CI GOPATH

- [x] 2.1 Point Main job checkout and `working-directory` at `go/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- [x] 2.2 Point race job checkout and `working-directory` at that same path

## 3. Local plugin loads

- [x] 3.1 Flip root `docker-compose.yml` from catalog `plugins.bouncer` + `version=v1.7.1` to `localPlugins` + bind-mount at the new module (same pattern as `docker-compose.local.yml`); keep alias `bouncer`
- [x] 3.2 Flip `examples/*/docker-compose.yml` that already have commented localPlugins + bind-mount; add the same pair on `examples/behind-proxy/docker-compose.yml`; remove catalog `version=` for this module
- [x] 3.3 Retarget already-local paths only: `examples/geoenrich-decisions`, `tests/e2e/real`, `tests/e2e/mock` (`modulename` + `plugins-local/src/<module>`); do not retarget geoblock
- [x] 3.4 Switch Kubernetes values and binary-vm static config from `experimental.plugins` + `version` to `localPlugins` at the new moduleName; document the operator mount/copy to `plugins-local/src/<module>`

## 4. Docs and live specs

- [x] 4.1 README working static example: `localPlugins` + alias `bouncer`; note catalog 404 / fork-ban and a different operator alias when upstream `plugins.bouncer` is kept
- [x] 4.2 Change usage `knowledge/devdocs/core_plugin_middleware.md` “Do not change import” to keep import matching `go.mod`
- [x] 4.3 Leave `openspec/changes/archive/**` and `renovate.json` alone

## 5. Verify

- [x] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/...`, `go test .`
- [x] 5.2 Confirm no remaining product-tree load path still names `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` except debt/research/archive and `renovate.json`
