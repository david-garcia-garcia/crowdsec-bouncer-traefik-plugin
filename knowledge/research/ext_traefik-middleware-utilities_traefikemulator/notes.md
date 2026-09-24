# traefikemulator at utilities v1.0.7

Tag `v1.0.7` is commit `42e6a1a967155318023c4defe491d1d423e165b6`. That tree publishes package `traefikemulator` at module root (not under `pkg/`). Tag `v1.0.6` has no `traefikemulator/` directory.

## API

- `Constructor` = `func(ctx context.Context, next http.Handler, config any, middlewareName string) (http.Handler, error)`
- `Route` fields: `Name`, `MiddlewareName`, `Next`, `Config`
- `New(Constructor) *Emulator` — nil constructor panics
- `Apply([]Route) map[string]error` — cancel previous generation, one shared context, omit failed routes, leave generation live
- `Stop()`, `Handler(routeName) (http.Handler, bool)`, `Serve(routeName, w, req) bool`

`traefikemulator/emulator.go` at that commit is git-blob `3e023e0931700cddef3d6ee8450119c54ae291f1`, the same blob as this plugin's `pkg/traefikemulator/emulator.go`.

Upstream `emulator_test.go` covers the same generation/Serve cases as `pkg/traefikemulator/zzz_emulator_test.go` plus nil-New, duplicate route, Stop, and empty Apply.

Sources: `.sources/emulator-go.md`, `.sources/emulator-test-go.md`.
