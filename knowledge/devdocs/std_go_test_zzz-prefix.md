## Language

**zzz_ test file**:
An in-repo Go test source whose basename starts with `zzz_` and ends with `_test.go`.
_Avoid_: appending `zzz_` after `_test.go`; a trailing `zzz_` is not a test file.

## How to use

- Name a new in-repo test `zzz_<stem>_test.go` in the same package directory.
- Do not prefix files under `vendor/`.
- Do not rename production `.go` files.

## Pattern snippet

```
pkg/cache/zzz_cache_test.go
zzz_bouncer_test.go
```

## Key files

- in-repo `zzz_*_test.go` next to the package under test

## Gotchas

- `go test` only loads basenames that end in `_test.go`. `cache_testzzz_.go` is ignored.
