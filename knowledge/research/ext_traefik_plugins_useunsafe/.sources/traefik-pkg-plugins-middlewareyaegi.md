---
url: https://github.com/traefik/traefik/blob/d48621ce0b6fd221b20bdb6c22e652e7498e5db6/pkg/plugins/middlewareyaegi.go
title: traefik pkg/plugins — Yaegi interpreter setup and useUnsafe gate
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@d48621ce0b6fd221b20bdb6c22e652e7498e5db6:pkg/plugins/middlewareyaegi.go
---

The file that decides what a Yaegi plugin may import.

## Imports

```go
import (
	"context"; "errors"; "fmt"; "net/http"; "os"; "path"; "reflect"; "strings"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"github.com/traefik/yaegi/stdlib/syscall"
	"github.com/traefik/yaegi/stdlib/unsafe"
)
```

## newInterpreter — the whole gate

```go
func newInterpreter(ctx context.Context, goPath string, manifest *Manifest, settings Settings) (*interp.Interpreter, error) {
	i := interp.New(interp.Options{
		GoPath: goPath,
		Env:    os.Environ(),
		Stdout: logs.NoLevel(*log.Ctx(ctx), zerolog.DebugLevel),
		Stderr: logs.NoLevel(*log.Ctx(ctx), zerolog.ErrorLevel),
	})

	err := i.Use(stdlib.Symbols)
	if err != nil {
		return nil, fmt.Errorf("failed to load symbols: %w", err)
	}

	if manifest.UseUnsafe && !settings.UseUnsafe {
		return nil, errors.New("this plugin uses restricted imports. If you want to use it, you need to allow useUnsafe in the settings")
	}

	if settings.UseUnsafe && manifest.UseUnsafe {
		err := i.Use(unsafe.Symbols)
		if err != nil {
			return nil, fmt.Errorf("failed to load unsafe symbols: %w", err)
		}

		err = i.Use(syscall.Symbols)
		if err != nil {
			return nil, fmt.Errorf("failed to load syscall symbols: %w", err)
		}
	}

	err = i.Use(ppSymbols())
	if err != nil {
		return nil, fmt.Errorf("failed to load provider symbols: %w", err)
	}

	_, err = i.Eval(fmt.Sprintf(`import "%s"`, manifest.Import))
	if err != nil {
		return nil, fmt.Errorf("failed to import plugin code %q: %w", manifest.Import, err)
	}

	return i, nil
}
```

Claims this owns:

- The plugin is loaded by `i.Eval(import ...)` on the interpreter in every branch. `useUnsafe`
  never switches to a compiled/native load path.
- The only difference the flag makes is two extra `i.Use(...)` symbol tables: `unsafe.Symbols`
  and `syscall.Symbols`, both from `github.com/traefik/yaegi/stdlib/...`.
- Manifest-only (`manifest.UseUnsafe && !settings.UseUnsafe`) is a hard startup error.
- Settings-only (`settings.UseUnsafe` without `manifest.UseUnsafe`) loads nothing extra — the
  second `if` requires both.
- After construction the plugin is still driven through `i.Eval(basePkg + ".New")` and
  `i.Eval(basePkg + ".CreateConfig")` (`newYaegiMiddlewareBuilder`), i.e. reflection over
  interpreted functions.

## pkg/plugins/types.go — same commit

```go
type Settings struct {
	Envs      []string `description:"Environment variables to forward to the wasm guest." json:"envs,omitempty" toml:"envs,omitempty" yaml:"envs,omitempty"`
	Mounts    []string `description:"Directory to mount to the wasm guest." json:"mounts,omitempty" toml:"mounts,omitempty" yaml:"mounts,omitempty"`
	UseUnsafe bool     `description:"Allow the plugin to use unsafe and syscall packages." json:"useUnsafe,omitempty" toml:"useUnsafe,omitempty" yaml:"useUnsafe,omitempty"`
}

// Descriptor The static part of a plugin configuration.   [catalog plugins]
type Descriptor struct {
	ModuleName string
	Version    string
	Hash       string
	Settings   Settings `description:"Plugin's settings (works only for wasm plugins)." ...`
}

// LocalDescriptor The static part of a local plugin configuration.
type LocalDescriptor struct {
	ModuleName string
	Settings   Settings `description:"Plugin's settings (works only for wasm plugins)." ...`
}

// Manifest The plugin manifest.
type Manifest struct {
	DisplayName   string         `yaml:"displayName"`
	Type          string         `yaml:"type"`
	Runtime       string         `yaml:"runtime"`
	WasmPath      string         `yaml:"wasmPath"`
	Import        string         `yaml:"import"`
	BasePkg       string         `yaml:"basePkg"`
	Compatibility string         `yaml:"compatibility"`
	Summary       string         `yaml:"summary"`
	UseUnsafe     bool           `yaml:"useUnsafe"`
	TestData      map[string]any `yaml:"testData"`
}

func (m *Manifest) IsYaegiPlugin() bool {
	return m.Runtime == runtimeYaegi || m.Runtime == ""
}
```

`Settings` is embedded in **both** `Descriptor` (catalog) and `LocalDescriptor` (local) — so
catalog plugins need the operator opt-in too.

The `"works only for wasm plugins"` description string on `Settings` conflicts with
`middlewareyaegi.go` reading `settings.UseUnsafe` on the Yaegi path. Source wins; the description
is stale and applies to `envs`/`mounts`.

## pkg/plugins/middlewareyaegi_test.go — confirms intent

```go
	Import:    "does-not-matter-will-error-before-import",
	UseUnsafe: true, // Plugin wants unsafe access
...
settings := Settings{
	UseUnsafe: false, // But admin doesn't allow it
}
```

The test name and comments state the two-party model explicitly: plugin asks, admin allows.

## Version presence check

`pkg/plugins/types.go` fetched at two release tags:

- `traefik/traefik@v3.4.0:pkg/plugins/types.go` — no `UseUnsafe` identifier.
- `traefik/traefik@v3.5.0:pkg/plugins/types.go` — `UseUnsafe` present.

So v3.5.0 is the first release carrying the feature.
