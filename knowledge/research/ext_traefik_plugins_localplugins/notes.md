# Local plugins

Traefik loads a local plugin through the same plugin machinery as a catalog plugin. The difference is the source: disk under `./plugins-local/src/<moduleName>` instead of a versioned download. That is not a mock of Traefik.

## Configure the alias

Install configuration (YAML, TOML, or CLI) declares `experimental.localPlugins.<alias>.moduleName`. The alias is the name used later in routing (`plugin.<alias>`). `moduleName` is the Go module path. There is no `version` field on `localPlugins`; catalog plugins use `experimental.plugins.<alias>` with both `moduleName` and `version`.

Owner: [Traefik v3.7 Plugins Experimental Configuration](https://doc.traefik.io/traefik/v3.7/reference/install-configuration/experimental/plugins/). Extract: `.sources/plugins-experimental.md`.

This tree’s local compose uses the CLI form and alias `bouncer`:

`--experimental.localplugins.bouncer.modulename=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`

Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.local.yml`. Extract: `.sources/docker-compose.local.yml.md`.

The non-local compose on the same tree uses the catalog form (`experimental.plugins.bouncer` plus `version=v1.7.1`) and does not bind-mount sources. Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.yml`. Extract: `.sources/docker-compose.yml.md`.

## Filesystem layout

The plugin tree must sit in `./plugins-local` relative to the Traefik process working directory, as a GOPATH-shaped workspace: `./plugins-local/src/<moduleName>/` (manifest `.traefik.yml`, `go.mod`, sources). Traefik loads that path instead of downloading.

Owner: [Working with Traefik Plugins — Local Mode](https://plugins.traefik.io/install). Extract: `.sources/working-with-traefik-plugins.md`.

v3.7.11 joins `localGoPath` (`./plugins-local/`), `src`, the module name, and `.traefik.yml`. Catalog installs still unzip into a `src/<module>` tree after download; local plugins skip the download.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go` and `pkg/plugins/manager.go`. Extracts: `.sources/plugins.go.md`, `.sources/manager.go.md`.

Plugins are parsed and loaded only at Traefik startup. A missing manifest disables plugins.

Owner: [Working with Traefik Plugins](https://plugins.traefik.io/install). Extract: `.sources/working-with-traefik-plugins.md`.

## Docker bind-mount

Official Traefik Hub docs mount the host module onto `/plugins-local/src/<moduleName>` and set `experimental.localPlugins` to that module name.

Owner: [Plugin Development Guide — Docker/Docker Compose](https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide). Extract: `.sources/plugin-development-guide.md`.

This tree does the same for `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`:

`./:/plugins-local/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`

Image pin on that file: `traefik:v3.7.11`. Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.local.yml`. Extract: `.sources/docker-compose.local.yml.md`.

The official `traefik` image copies the binary to `/` and sets `ENTRYPOINT ["/traefik"]` with no `WORKDIR`. Docker’s default working directory is `/`, so `./plugins-local` is `/plugins-local` inside the container.

Owners: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:Dockerfile` (no WORKDIR, binary at `/`). The CWD conclusion is inference from that Dockerfile plus Docker’s default. Extracts: `.sources/Dockerfile.md`.

## Not a mock of Traefik

Catalog docs describe local mode as the way to load private or in-development plugins. Traefik still interprets the real plugin. A Docker e2e suite that bind-mounts this module and sets `localPlugins` is exercising Traefik’s production plugin loader against in-tree sources, not a fake Traefik.

The mock e2e suite uses the same loader from a temp CWD (symlink into `plugins-local/src/...`) and a downloaded Traefik binary defaulting to `v3.7.11`. That suite mocks Crowdsec LAPI, not Traefik.

Owners: [Working with Traefik Plugins](https://plugins.traefik.io/install); `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:tests/e2e/mock/lib/common.sh`. Extracts: `.sources/working-with-traefik-plugins.md`, `.sources/common.sh.md`.
