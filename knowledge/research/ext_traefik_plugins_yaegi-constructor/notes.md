# Yaegi middleware constructor

Traefik Yaegi middleware plugins are a Go package whose **root import** exports `CreateConfig` and `New`. Traefik looks those two functions up by name in `basePkg`. It does not look up a type named `Config` for middleware. Subpackages are loadable as GOPATH imports; they cannot replace the root constructor.

Filesystem install (`plugins-local/src/<module>`) is a different finding: `ext_traefik_plugins_localplugins/`.

## Where CreateConfig and New must live

After Traefik creates a Yaegi interpreter, it evaluates `import "<manifest.Import>"`, then `Eval(basePkg + ".New")` and `Eval(basePkg + ".CreateConfig")`. Those identifiers must exist on the package Yaegi loaded for `import`. That is the module-root package in the official skeleton (`plugin.go` / `demo.go`), not a subpackage.

`CreateConfig` is called with no arguments and must return exactly one value (the config pointer). `New` is called as `(ctx, next, config, middlewareName)` and must return an `http.Handler` (and optionally an `error`).

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go`. Extract: `.sources/middlewareyaegi.go.md`.

The Hub guide states the same three exports and the `New` signature, with `Config` in the same file as a skeleton. Owner: [Plugin Development Guide — 1.4 Create Plugin Source Code](https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide). Extract: `.sources/plugin-development-guide.md`.

Official demo: `package plugindemo` at module root, `CreateConfig() *Config`, `New(ctx, next, config *Config, name)`. Owner: `github.com/traefik/plugindemo@01ec61f2084a7386143310735eb48eb3e990bd19:demo.go`. Extract: `.sources/demo.go.md`.

This plugin: `package crowdsec_bouncer_traefik_plugin` in `bouncer.go` exports both functions. Owner: `this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:bouncer.go`. Extract: `.sources/bouncer.go.md`.

## `.traefik.yml` `import` and `basePkg`

`Manifest.Import` and `Manifest.BasePkg` are YAML fields on `.traefik.yml`. Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/types.go`. Extract: `.sources/types.go.md`.

**`import` (required for Yaegi):** the Go import path passed to Yaegi (`import "<import>"`). Hub: must match the repository / `go.mod` module path. Traefik also checks that `import` has prefix `moduleName` (the catalog or `localPlugins` module name). Empty `import` is a manifest error for Yaegi plugins.

Owners: [Plugin Development Guide — Manifest Fields Reference](https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide); `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go` (`checkLocalPluginManifest`). Extracts: `.sources/plugin-development-guide.md`, `.sources/plugins.go.md`.

This plugin: `import: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` and no `basePkg`. Owner: `this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:.traefik.yml`. Extract: `.sources/traefik.yml.md`. Demo: `import: github.com/traefik/plugindemo`. Owner: `github.com/traefik/plugindemo@01ec61f2084a7386143310735eb48eb3e990bd19:.traefik.yml`. Extract: `.sources/plugindemo.traefik.yml.md`.

**`basePkg` (optional):** the Go package identifier used to eval `New` / `CreateConfig`. If empty, Traefik sets `strings.ReplaceAll(path.Base(import), "-", "_")`. For this plugin that yields `crowdsec_bouncer_traefik_plugin`, which matches `bouncer.go`’s package clause, so `basePkg` can be omitted. Set `basePkg` when the package clause does not match that derivation.

Owners: Hub Manifest Fields Reference (`basePkg` auto-derived from `import`); `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go` (`newYaegiMiddlewareBuilder`). Extracts: `.sources/plugin-development-guide.md`, `.sources/middlewareyaegi.go.md`.

The catalog create page only says a Yaegi plugin is a Go package and points at plugindemo. Owner: [Developing Traefik Plugins](https://plugins.traefik.io/create). Extract: `.sources/developing-traefik-plugins.md`.

## Does Traefik call New once per middleware / route?

Not once per Traefik process, and not once per request.

1. **Startup (once per plugin alias):** `NewBuilder` builds one Yaegi interpreter and looks up `New` / `CreateConfig` as function values. It does not call `New`. Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/builder.go`. Extract: `.sources/builder.go.md`.

2. **Each time a router HTTP handler is built:** `buildHTTPHandler` takes that router’s middleware name list, `BuildMiddlewareChain` appends a constructor per name, and `alice.Then` runs it. For a plugin, `buildConstructor` calls `pluginBuilder.Build` (which **calls `CreateConfig`** and mapstructure-decodes the named middleware’s config), then `constructor(next)` → `newTraceablePlugin` → `plug(ctx, next)` → `YaegiMiddleware.NewHandler` → **`New`**.

Owners: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/server/router/router.go` (`buildHTTPHandler`); `pkg/server/middleware/middlewares.go` (`BuildMiddlewareChain`, plugin branch of `buildConstructor`); `pkg/server/middleware/plugins.go` (`newTraceablePlugin`); `pkg/plugins/middlewareyaegi.go` (`NewHandler`). Extracts: `.sources/router.go.md`, `.sources/middlewares.go.md`, `.sources/server-plugins.go.md`, `.sources/middlewareyaegi.go.md`.

Two routers that both list the same named middleware therefore each get their own `New` call (and their own `CreateConfig` call) when their handlers are built. `buildRouterHandler` caches the finished handler by `routerName` on that `Manager`, so `New` is not per request. A dynamic-config reload that constructs a new `Manager` builds handlers again.

This plugin’s comment that Traefik creates an instance per route matches that router-handler build, not a per-request factory. Owner: `this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:bouncer.go`. Extract: `.sources/bouncer.go.md`.

## Must Config be a type named Config in the root package?

**Middleware: no.** Traefik never evals `basePkg.Config`. It uses the pointer `CreateConfig` returns as mapstructure `Result`, then passes that same `reflect.Value` as `New`’s third argument. `CreateConfig() *configuration.Config` is valid if `New` takes that same type.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go` (`createConfig`, `newHandler`). Extract: `.sources/middlewareyaegi.go.md`.

This plugin does that: `CreateConfig() *configuration.Config` with `Config` defined in `pkg/configuration`. Owners: `this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:bouncer.go`, `pkg/configuration/configuration.go`. Extracts: `.sources/bouncer.go.md`, `.sources/configuration.go.md`.

Official Hub text says the plugin must export a Config struct and shows `type Config` next to `CreateConfig` / `New`. That is the published skeleton, not what the middleware loader looks up. Follow **source** for v3.7.11 middleware; treat Hub/plugindemo as the catalog starting point. Owners: Hub 1.4; `github.com/traefik/plugindemo@01ec61f2084a7386143310735eb48eb3e990bd19:demo.go`. Extracts: `.sources/plugin-development-guide.md`, `.sources/demo.go.md`.

**Provider plugins are different:** the Yaegi wrapper is generated with `config *basePkg.Config`. A provider must export a type named `Config` in `basePkg`. This product is a middleware (`type: middleware`). Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/providers.go`. Extract: `.sources/providers.go.md`.

## Subpackages

Traefik’s interpreter is created with `interp.Options{GoPath: goPath}` and only `import`s `manifest.Import`. Further imports from that package (for example `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache`) resolve as GOPATH packages under `goPath/src/<module>/…`. Traefik does not require a single-file plugin.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go` (`newInterpreter`). Extract: `.sources/middlewareyaegi.go.md`.

Hub local-dev tree lists `plugin.go`, `go.mod`, `.traefik.yml` as the starting layout. That is a skeleton, not a ban on `pkg/`. Owner: [Plugin Development Guide — Local Plugin Development](https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide). Extract: `.sources/plugin-development-guide.md`.

This plugin already keeps `CreateConfig` / `New` on the root package and imports `pkg/cache`, `pkg/captcha`, `pkg/configuration`, `pkg/ip`, `pkg/logger`. Owner: `this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:bouncer.go`. Extract: `.sources/bouncer.go.md`.
