---
url: https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide
title: Plugin Development Guide — Traefik Hub API Gateway
fetched: 2026-09-05
authority: official
---

Official Traefik documentation for the `.traefik.yml` plugin manifest.

## Manifest field table (claims used)

| Field | Required | Description | Notes |
|---|---|---|---|
| `displayName` | Yes | Plugin name displayed in the catalog and logs | Example: `"My Custom Plugin"` |
| `type` | Yes | Plugin type | `middleware` or `provider` |
| `import` | Yes | Your plugin's Go import path | Must match repository: `github.com/my-org/my-plugin` |
| `summary` | Yes | Brief description of plugin functionality | Displayed in the Plugin Catalog |
| `testData` | Yes | Sample configuration for testing the plugin | Key-value pairs matching your plugin's Config struct |
| `runtime` | Optional | Plugin runtime interpreter | `yaegi` (default) or `wasm`. Provider plugins only support `yaegi` |
| `wasmPath` | Optional | Path to WebAssembly binary | Required if `runtime: wasm`. Defaults to `plugin.wasm` |
| `basePkg` | Optional | Base package name for the plugin | Auto-derived from `import` if not specified |
| `compatibility` | Optional | Traefik version compatibility requirement | Example: `>= 2.10.0` |
| **`useUnsafe`** | **Optional** | **Allow plugin to use `unsafe` and `syscall` packages** | **Defaults to `false`. Security implications apply** |

Two facts this establishes:

- `useUnsafe` covers **both** `unsafe` and `syscall`, not `unsafe` alone.
- It is `false` by default, and the docs explicitly flag security implications.

## Runtime context

> Provider plugins only support the `yaegi` runtime (the default). The `wasm` runtime is not
> supported for provider plugins. If you're developing a provider plugin, omit the `runtime` field
> or explicitly set it to `yaegi` in your `.traefik.yml`.

`runtime` and `useUnsafe` are independent fields. `useUnsafe` is not a runtime selector — the page
lists `yaegi` and `wasm` as the only runtimes, with no "native" or "compiled" option.
