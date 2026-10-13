## 1. Cache Debug attributes

- [x] 1.1 Replace Get/GetMany/Set/Delete `Sprintf`+Debug with slog attributes (`cache:Get` + `key`, `cache:GetMany` + `keys`, `cache:Set` + `key`/`value`/`duration`, `cache:Delete` + `key`). Leave `cache.New` and `Acquire`.

## 2. ServeHTTP Debug attributes

- [x] 2.1 Replace every Debug `Sprintf`/`+` in `ServeHTTP` with slog attributes. Reuse `req.remoteIP` and `isTrusted`. Leave Error/Warn, `handleRemediationServeHTTP`, and AppSec Debug.

## 3. Tests

- [x] 3.1 Add a package log sink in `pkg/cache` if missing. Assert DEBUG Get/GetMany records use message stems plus attributes (DestBranch interpolated `msg=` fails).
- [x] 3.2 Add a package log sink in `pkg/bouncer` if missing. Assert DEBUG ServeHTTP record is `ServeHTTP` with `ip` and `isTrusted` attributes.

## 4. Verify

- [x] 4.1 `go test ./pkg/cache/ ./pkg/bouncer/ -count=1` passes
- [x] 4.2 Existing logger construct tests stay green (`go test ./pkg/logger/ -count=1`)
