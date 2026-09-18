# LimitReader zero and negative limit

How Go `io.LimitReader` / `LimitedReader` behaves when `N <= 0`. An implementer who wants “no cap” cannot pass `0` into `LimitReader`.

Fetched: 2026-09-17. Pin: Go 1.25.6 (`go version go1.25.6 windows/amd64`).

## `N <= 0` is immediate EOF

`LimitReader(r, n)` returns a `*LimitedReader` with `N` set to `n`. `LimitedReader.Read` returns `0, EOF` when `N <= 0` before it touches `R`. ([io.go](https://github.com/golang/go/blob/go1.25.6/src/io/io.go), extract `.sources/io.go.md`; [pkg.go.dev/io](https://pkg.go.dev/io#LimitedReader))

`io.ReadAll` on that reader therefore yields an empty slice and a nil error (`ReadAll` treats `EOF` as success). Local probe on Go 1.25.6: `LimitReader(strings.NewReader("hello"), 0)` and `n=-1` both produced `bytes="" err=<nil>`. (authority: inference — `.sources/local-go1256-limitreader-probe.md`)

## What this means for an “unlimited” cap

Passing the operator value `0` into `io.LimitReader` does **not** mean “read everything”. It means “read nothing”. Unlimited must skip `LimitReader` and read `R` directly (for example `io.ReadAll(r)`).

There is no official `LimitReader` sentinel for unlimited. `n` is a remaining-byte counter, not a disable flag.

## Sources

- Official: [io.LimitedReader](https://pkg.go.dev/io#LimitedReader)
- Source: `golang/go@go1.25.6:src/io/io.go`
- Extracts: `.sources/`
