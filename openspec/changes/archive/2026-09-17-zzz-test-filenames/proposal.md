## Why

Dest `main` names every Go test file as a plain `*_test.go` basename with no `zzz_` token. The ticket asks to add that token to each test filename so the on-disk names carry the marker.

## What Changes

- Rename every in-repo Go test file (`*_test.go`, excluding `vendor/`) so the current basename is prefixed with `zzz_` (example: `cache_test.go` → `zzz_cache_test.go`).
- Keep the required `_test.go` suffix so `go test ./...` still discovers the same packages.
- Update the one `README.md` tree line that names `bouncer_test.go`.

## Capabilities

### New Capabilities

- `std_go_test_zzz-prefix`: house rule that in-repo Go test sources use a `zzz_` prefix on the basename and still end in `_test.go`.

### Modified Capabilities

None.

## Impact

- Five dest-`main` files today: `bouncer_test.go`, `bouncer_logging_test.go`, `pkg/cache/cache_test.go`, `pkg/configuration/configuration_test.go`, `pkg/logger/logger_test.go`. Any extra in-repo `*_test.go` present at apply after Sync is included.
- `Makefile` `test` (`go test -v -cover ./...`) and `.golangci.yml` `(.+)_test.go` keep working without edits.
- No runtime, config, or public API change.
