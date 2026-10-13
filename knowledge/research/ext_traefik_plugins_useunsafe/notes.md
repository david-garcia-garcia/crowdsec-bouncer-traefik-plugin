# Plugin manifest useUnsafe

`useUnsafe` is a boolean in a Traefik plugin's `.traefik.yml` manifest. It widens the symbol set the
Yaegi interpreter exposes to the plugin. It does not change *how* the plugin is loaded.

Pinned for this finding: `github.com/traefik/traefik@d48621ce0b6fd221b20bdb6c22e652e7498e5db6`.

## What the manifest field is

> `useUnsafe` | Optional | Allow plugin to use `unsafe` and `syscall` packages | Defaults to `false`. Security implications apply

Source: <https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide> (extract: `.sources/traefik-hub-plugin-development-guide.md`).

Declared on the manifest struct as `UseUnsafe bool` with tag `yaml:"useUnsafe"`.
Source: `traefik/traefik@d48621c:pkg/plugins/types.go`.

## What it actually unlocks

Exactly two extra Yaegi symbol tables, and nothing else. In `newInterpreter`:

```go
i := interp.New(interp.Options{GoPath: goPath, Env: os.Environ(), ...})

err := i.Use(stdlib.Symbols)            // always

if manifest.UseUnsafe && !settings.UseUnsafe {
    return nil, errors.New("this plugin uses restricted imports. If you want to use it, you need to allow useUnsafe in the settings")
}

if settings.UseUnsafe && manifest.UseUnsafe {
    err := i.Use(unsafe.Symbols)        // github.com/traefik/yaegi/stdlib/unsafe
    ...
    err = i.Use(syscall.Symbols)        // github.com/traefik/yaegi/stdlib/syscall
    ...
}

err = i.Use(ppSymbols())
_, err = i.Eval(fmt.Sprintf(`import "%s"`, manifest.Import))
```

Source: `traefik/traefik@d48621c:pkg/plugins/middlewareyaegi.go` (extract: `.sources/traefik-pkg-plugins-middlewareyaegi.md`).

Three things follow directly from that code:

1. **Still Yaegi.** The `i.Eval(import ...)` line is unchanged and unconditional. The plugin is
   interpreted source either way. `useUnsafe` does **not** enable compiled native Go plugins,
   `plugin.Open`, cgo, or the `wasm` runtime.
2. **Only the stdlib `unsafe` and `syscall` packages.** `i.Use` adds pre-generated symbol tables
   from `yaegi/stdlib/unsafe` and `yaegi/stdlib/syscall`. It does not open the door to arbitrary
   third-party libraries — those still have to be interpretable by Yaegi and vendored into the
   plugin's `GoPath` like any other dependency.
3. **The flag is a gate, not a grant, on its own.** Setting it in the manifest without the operator
   opt-in makes the plugin fail to load with the error string above.

The original PR states the same intent: "This PR provides a way to enable the use of the `unsafe`
package in the go standard library within yaegi by adding a flag in the plugin manifest."
Source: <https://github.com/traefik/traefik/pull/11589> (extract: `.sources/traefik-pr-11589.md`).

### Yaegi symbol coverage

`yaegi/stdlib/syscall` symbol tables are generated per Go version and per GOOS/GOARCH; the latest
generated set is `go1_22_*` (e.g. `go1_22_syscall_linux_amd64.go`). `yaegi/stdlib/unsafe` likewise
tops out at `go1_22_unsafe.go`. For `linux/amd64`, `Recvfrom`, `MSG_PEEK`, `MSG_DONTWAIT`, `EAGAIN`,
`Conn`, and `RawConn` are all present in that table.
Source: `traefik/yaegi@master:stdlib/syscall/`, `traefik/yaegi@master:stdlib/unsafe/` (extract: `.sources/yaegi-stdlib-restricted-symbols.md`).

### Necessary, not sufficient — Yaegi's own limits remain

Enabling `useUnsafe` removes the *import* restriction. It does not remove Yaegi's interpretation
limits. On [traefik/traefik#11938](https://github.com/traefik/traefik/issues/11938), a reporter
loaded a go-redis-based plugin with syscall enabled and it then panicked at runtime with
`reflect.Value.Interface: cannot return value obtained from unexported field or method`,
diagnosed on-thread as a Yaegi limitation with modules that use reflection (2025-10-15, 2025-10-20).
`authority: comment` — reporter accounts on a vendor issue tracker, not a Traefik maintainer
statement. Treat as reproduction evidence, not as a specification.
Extract: `.sources/traefik-issue-11938.md`.

## The operator must opt in separately — catalog plugins included

`useUnsafe` in the manifest is *not* sufficient. The Traefik installation must also set
`settings.useUnsafe` in its static configuration, or the plugin fails to start:

```go
if manifest.UseUnsafe && !settings.UseUnsafe {
    return nil, errors.New("this plugin uses restricted imports. ...")
}
```

Source: `traefik/traefik@d48621c:pkg/plugins/middlewareyaegi.go`.

The `Settings` struct is embedded in **both** descriptor types, so the opt-in applies to catalog
plugins and local plugins alike:

- `experimental.plugins.<name>.settings.useUnsafe` — catalog (`Descriptor.Settings`)
- `experimental.localPlugins.<name>.settings.useUnsafe` — local (`LocalDescriptor.Settings`)

Sources: `traefik/traefik@d48621c:pkg/plugins/types.go`;
`traefik/traefik@d48621c:docs/content/reference/install-configuration/configuration-options.md`;
`traefik/traefik@d48621c:docs/content/reference/static-configuration/file.yaml` (extract: `.sources/traefik-docs-experimental-plugins.md`).

This was a deliberate review requirement, not an accident. Traefik maintainer `rtribotte` on the PR:

> Add an option to the plugin settings configuration to allow the use of the `unsafe` package.
> It's the opt-in part for the Traefik user. If this option is missing, the plugin should fail to start.

Source: <https://github.com/traefik/traefik/pull/11589>.

### Conflict: docs say "wasm only"

The reference docs annotate `settings` as "Plugin's settings (works only for wasm plugins)", and the
`Descriptor.Settings` / `LocalDescriptor.Settings` struct tags carry that same string.
That description is stale — `settings.useUnsafe` is read on the **Yaegi** path in
`pkg/plugins/middlewareyaegi.go`, and the docs table immediately below lists
`settings.useUnsafe` as "Allow the plugin to use unsafe and syscall packages."

Per source-over-official for what this version does: follow the source. `settings.useUnsafe`
applies to Yaegi plugins at `traefik/traefik@d48621c`. Only `settings.envs` and `settings.mounts`
are wasm-specific.

## Availability

Merged 2025-04-25 (merge commit `8f37c8f0c54d5bba62eadbb7cd633267de939c32`, PR
[traefik/traefik#11589](https://github.com/traefik/traefik/pull/11589)).

First shipped in **Traefik v3.5.0** (released 2025-07-23), not v3.4.0. Verified by reading
`pkg/plugins/types.go` at both tags: `UseUnsafe` is absent at `v3.4.0` and present at `v3.5.0`.
The v3.5.0 CHANGELOG lists it under `**[plugins]** Ability to enable unsafe in yaegi through plugin manifest`.
Source: `traefik/traefik@v3.4.0:pkg/plugins/types.go`, `traefik/traefik@v3.5.0:pkg/plugins/types.go`,
`traefik/traefik@master:CHANGELOG.md`.

Catalog-side support required two further merges, both now done:

- [traefik/piceus#110](https://github.com/traefik/piceus/pull/110) "Adds useUnsafe" — merged 2025-06-10. Body: "The useUnsafe disable the yaegi plugin verification." Piceus normally runs the plugin's `New` and `CreateConfig` when indexing; an unsafe-marked plugin bypasses that check.
- traefik/plugin-service#69 — referenced by maintainer `juliens` on 2025-04-25 as the remaining catalog dependency.

Source: <https://github.com/traefik/piceus/pull/110>, <https://github.com/traefik/traefik/pull/11589>.

## Bearing on this repo

This repo's `.traefik.yml` does not set `useUnsafe` (`crowdsec-bouncer-traefik-plugin:.traefik.yml`,
`authority: source`). Adding it would raise the minimum supported Traefik to v3.5.0 and would require
every operator to also set `settings.useUnsafe` in static configuration — an out-of-band change no
plugin-side release can make for them.
`authority: inference` — derived from the gate in `middlewareyaegi.go` and the tag comparison above.

For the client library that motivates this, see `knowledge/research/ext_redis_go-redis/notes.md`.
For how Traefik resolves the plugin entrypoint at all, see
`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`.
