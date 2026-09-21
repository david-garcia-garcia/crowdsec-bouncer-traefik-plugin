---
url: https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/docs/content/reference/install-configuration/experimental/plugins.md
title: traefik docs — experimental plugins static configuration
fetched: 2026-09-05
authority: official
ref: github.com/traefik/traefik@d48621ce0b6fd221b20bdb6c22e652e7498e5db6:docs/content/reference/install-configuration/
---

Traefik's own reference docs for the operator-side plugin settings.

## docs/content/reference/install-configuration/experimental/plugins.md

| Option | Description | Type | Required |
|---|---|---|---|
| `settings` | Plugin's settings (works only for wasm plugins). | object | No |
| `settings.envs` | Environment variables to forward to the wasm guest. | []string | No |
| `settings.mounts` | Directory to mount to the wasm guest. | []string | No |
| `settings.useUnsafe` | Allow the plugin to use unsafe and syscall packages. | bool | No |

Note the internal inconsistency: the parent `settings` row says "works only for wasm plugins",
while `settings.useUnsafe` describes a Yaegi-only capability. `pkg/plugins/middlewareyaegi.go`
(authority: source) settles it — `useUnsafe` is read on the Yaegi path.

## docs/content/reference/install-configuration/configuration-options.md

Both plugin descriptor kinds expose it:

| Option | Description | Default |
|---|---|---|
| `experimental.localplugins._name_.settings.useunsafe` | Allow the plugin to use unsafe and syscall packages. | `false` |
| `experimental.plugins._name_.…` | (catalog descriptors: `modulename`, `version`, `hash`, `settings.…`) | |

## docs/content/reference/static-configuration/file.yaml

The generated full-reference static config shows `useUnsafe` under **both** blocks:

```yaml
experimental:
  plugins:
    Descriptor0:
      moduleName: foobar
      version: foobar
      hash: foobar
      settings:
        envs:
          - foobar
        mounts:
          - foobar
        useUnsafe: true
    Descriptor1:
      ...
  localPlugins:
    LocalDescriptor0:
      moduleName: foobar
      settings:
        envs:
          - foobar
        mounts:
          - foobar
        useUnsafe: true
```

## docs/content/reference/static-configuration/file.toml

```toml
[experimental.plugins.Descriptor0.settings]
  envs = ["foobar", "foobar"]
  mounts = ["foobar", "foobar"]
  useUnsafe = true

[experimental.localPlugins.LocalDescriptor0.settings]
  envs = ["foobar", "foobar"]
  mounts = ["foobar", "foobar"]
  useUnsafe = true
```

Claim this owns: catalog plugins (`experimental.plugins`) require the operator opt-in exactly as
local plugins (`experimental.localPlugins`) do. Default is `false` in both.
