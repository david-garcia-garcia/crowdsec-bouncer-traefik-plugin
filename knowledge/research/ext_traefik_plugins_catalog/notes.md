# Catalog plugins

Catalog install is `experimental.plugins.<alias>` with **moduleName and version**. Traefik downloads that pair from `https://plugins.traefik.io/public/` at startup. Local bind-mount is a different finding: `ext_traefik_plugins_localplugins/`. Yaegi constructors: `ext_traefik_plugins_yaegi-constructor/`.

## Download

`SetupRemotePlugins` walks the catalog map and calls `InstallPlugin` per alias. `InstallPlugin` downloads then unzips into `sources/src/<moduleName>`. A non-OK download fails the install (`unable to download plugin`).

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go` (`SetupRemotePlugins`) and `pkg/plugins/manager.go` (`InstallPlugin`, `pluginsURL`). Extracts: `.sources/plugins.go.md`, `.sources/manager.go.md`.

The download URL is `{pluginsURL}download/{moduleName}/{version}` (`https://plugins.traefik.io/public/download/...`). Non-200 is an error.

Owner: `github.com/traefik/traefik@f6b7940b761abe0d16ee4b03588a0318481d86d8:pkg/plugins/client.go` (`Download`). That commit split the helper; v3.7.11 (`faa1eb59`) already has the same `pluginsURL` on `manager.go`. Extract: `.sources/client.go.md`.

Measured 2026-09-18 (GET, no body saved):

| moduleName | version | HTTP |
|---|---|---|
| `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` | `v1.7.1` | 200 |
| `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` | `v1.7.1` | 404 |
| `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` | `vX.Y.Z` | 404 |

Authority: inference from those responses. Official docs do not publish a “404 means unpublished” sentence; `Download` treats any non-200 as failure. Extract: `.sources/catalog-download-status.md`.

## Catalog will not list a fork

The catalog polls public GitHub daily. Checklist includes: **the repository is not a fork — forks are not added**. Also required: `traefik-plugin` topic, `.traefik.yml` with `testData`, `go.mod`, git tags, vendored deps.

Owner: [Developing Traefik Plugins](https://plugins.traefik.io/create). Extract: `.sources/developing-traefik-plugins.md`.

This GitHub repo is a fork of `maxlerebourg/crowdsec-bouncer-traefik-plugin`. Catalog listing of this module is not something a later in-tree change can satisfy without leaving the fork relationship (out of scope).

## Alias is the routing key

`experimental.plugins.<plugin-name>` / `experimental.localPlugins.<plugin-name>`: **plugin-name is the name used in routing** (`plugin.<alias>`). `moduleName` is the Go module path. Catalog also requires `version`. Local plugins have no version.

Owner: [Traefik v3.7 Plugins Experimental Configuration](https://doc.traefik.io/traefik/v3.7/reference/install-configuration/experimental/plugins/). Extract: `.sources/plugins-experimental.md`.

Two catalog plugins in one process use two aliases (official install page: `block` + `rewrite`). Owner: [Working with Traefik Plugins](https://plugins.traefik.io/install). Extract: `.sources/working-with-traefik-plugins.md`.

`checkRemotePluginsConfiguration` / `SetupLocalPlugins` reject a **duplicate moduleName** in the same map. They do not compare aliases across `plugins` and `localPlugins`.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go`. Extract: `.sources/plugins.go.md`.

`NewBuilder` fills `middlewareBuilders` from catalog first, then local plugins. **The same alias is a map write**: local overwrites catalog. Operators who keep upstream `experimental.plugins.bouncer` and also register this fork as `localPlugins.bouncer` do not get two plugins — they get the local one under that key.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/builder.go`. Extract: `.sources/builder.go.md`.

## Manifest import and displayName

Yaegi local-manifest check: `import` must be a prefix of `moduleName`. Empty `displayName` is a manifest error.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go` (`checkLocalPluginManifest`). Extract: `.sources/plugins.go.md`.
