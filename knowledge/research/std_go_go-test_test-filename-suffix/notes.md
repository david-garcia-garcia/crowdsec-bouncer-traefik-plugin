# Go test _test.go filename suffix

## Summary

`go test` and `go test ./...` discover tests by building each listed package together with extra sources whose **basename** matches the file pattern `*_test.go` (documented on `go help test`). In the Go 1.25.6 toolchain, that pattern is implemented as `strings.HasSuffix(name, "_test.go")` while scanning directory entries in `go/build`—equivalent to `*_test.go` for normal `.go` basenames.

A basename must end with the literal suffix `_test.go` (immediately before the final `.go` extension). Names that only contain `_test` elsewhere, or that break the `.go` extension, are **not** test files.

| Basename | Test file for `go test`? |
|----------|---------------------------|
| `cache_test.go` | Yes |
| `cache_testzzz_.go` | No — suffix is `zzz_.go`, not `_test.go` |
| `cache_test.gozzz_` | No — not a `.go` source (extension is `.gozzz_`) |

## Normal build vs test build

- `go build` on a package **ignores** sources classified as test files (those ending in `_test.go`); they are not part of `GoFiles` ([`go help build`](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies)).
- `go test` **adds** those same `_test.go`-suffixed files when compiling the test binary ([`go help test`](https://pkg.go.dev/cmd/go#hdr-Test_packages)).

## Ignored names

During package loading, basenames starting with `_` or `.` are skipped entirely ([`go/build` `matchFile`](https://github.com/golang/go/blob/go1.25.6/src/go/build/build.go)). That is why `go help test` says files beginning with `_` are ignored “(including `_test.go`)”: a file literally named `_test.go` is excluded, not `foo_test.go`.

## `./...` pattern

`go test ./...` uses the same per-package test build; the `./...` only expands import paths—it does not change the `_test.go` suffix rule.

## Non–test-file names with `Test*` functions

If a `.go` file is not classified as a test file (for example `cache_testzzz_.go`), `testing.T` functions in it are **not** executed; `go test` reports `[no test files]` when no `_test.go`-suffixed files exist in the package (verified locally with Go 1.25.6).

## Sources

- Tutorial: [Add a test](https://go.dev/doc/tutorial/add-a-test) — names ending in `_test.go`.
- Reference: [`go help test`](https://pkg.go.dev/cmd/go#hdr-Test_packages) — pattern `*_test.go`, ignored `_`/`.` prefixes.
- Reference: [`go help build`](https://pkg.go.dev/cmd/go#hdr-Compile_packages_and_dependencies) — build ignores `_test.go` files.
- Implementation: [`golang/go@go1.25.6` `src/go/build/build.go`](https://github.com/golang/go/blob/go1.25.6/src/go/build/build.go) — `HasSuffix(name, "_test.go")`, `TestGoFiles` / `GoFiles` split.
- Local check (authority: inference): temp module, Go 1.25.6 — see `.sources/local-go1256-filename-probe.md`.
