## 1. Pin and vendor

- [ ] 1.1 Require `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.7` in `go.mod` / `go.sum` (tag `v1.0.7`, commit `42e6a1a967155318023c4defe491d1d423e165b6`).
- [ ] 1.2 Run `go mod vendor`. Take published `vendor/.../reclaim/` and `vendor/.../traefikemulator/`. Do not re-apply dest `alias.go` or `table.go` edits. Leave simpleredis and iplookup sources unchanged.

## 2. Drop the local emulator

- [ ] 2.1 Re-search `*.go` for `pkg/traefikemulator` imports. Retarget every other-package import (today: `zzz_traefikemulator_test.go`) to `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator`.
- [ ] 2.2 Delete `pkg/traefikemulator/` including `zzz_emulator_test.go`. Do not copy those tests into this repo.
- [ ] 2.3 In `.golangci.yml` Test depguard, replace `…/pkg/traefikemulator` with `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator`.
- [ ] 2.4 Point `docs/traefikemulator.md` at the published import.

## 3. Keep the reclaim shim

- [ ] 3.1 Leave `pkg/reclaim` as the only product import of utilities reclaim. Do not import utilities reclaim from `plugin.go` or other product packages.
- [ ] 3.2 Confirm the shim compiles against published `SetAlias` / `Watch` / `ClearPublisher` / `Peek` / `Box` / `Published` with no local `table.go`.

## 4. Prove

- [ ] 4.1 Run `go test` for the emulator caller tests and `./pkg/reclaim/` (and any compile that would fail on a missing local emulator).
- [ ] 4.2 Confirm `go.mod` pin `v1.0.7` and `vendor/modules.txt` lists `traefikemulator` at that pin.

## 5. Leave neighbors

- [ ] 5.1 Do not change simpleredis or iplookup. Do not invent a new catalog leaf. Do not delete `pkg/reclaim`.
