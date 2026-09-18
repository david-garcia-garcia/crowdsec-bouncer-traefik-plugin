# Devdocs impact
change: retarget-plugin-module-path

## Units
- Middleware New — subsystem — `plugin.go` / `knowledge/devdocs/core_plugin_middleware.md` / `openspec/specs/core_plugin_middleware_bouncer`
- Local plugin — subsystem — `openspec/changes/retarget-plugin-module-path/specs/core_plugin_middleware_local-plugin` / `.traefik.yml` / compose `localPlugins`
- GitHub Actions GOPATH — pattern — `openspec/specs/build_ci_github_module-path` / `openspec/specs/build_ci_github_race-detector` / `.github/workflows/main.yml`

## Findings
- [x] missing-packet  Local plugin — no packet; only a How-to sentence on Middleware New
- [x] missing-packet  GitHub Actions GOPATH — no packet; no `build`/`ci` usage domain
