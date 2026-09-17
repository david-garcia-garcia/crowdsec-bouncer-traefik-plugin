# Explore

## Concepts

- **Go test file**: a source file whose name ends in `_test.go`. `make test` runs `go test -v -cover ./...`, which discovers those files by suffix. A rename that drops that suffix is a discovery change, not a rename.
- **`zzz_` marker**: the ticket asks to add the token `zzz_` to every such filename. The token is not a product feature; it only changes how the files sort and how they are named on disk.
- **Apply set**: dest `main` has five files. `Makefile` and CI do not list test files by name. `.golangci.yml` matches `(.+)_test.go`. `README.md` lists `bouncer_test.go` in a local-plugin tree.

```
CURRENT NAMES (dest main)
  bouncer_test.go
  bouncer_logging_test.go
  pkg/cache/cache_test.go
  pkg/configuration/configuration_test.go
  pkg/logger/logger_test.go

LITERAL APPEND (rejected)
  cache_test.go + zzz_  →  cache_test.gozzz_   // not *_test.go
  cache_testzzz_.go                              // not *_test.go

KEEP DISCOVERY
  zzz_cache_test.go     // prefix (sort-last token)
  cache_zzz_test.go     // insert before _test.go
```

## Decisions

- Rename only in-repo `*_test.go` files on the apply branch. Skip `vendor/`. Do not change test bodies, Makefile targets, CI YAML, or golangci rules.
- Keep the `_test.go` suffix so `go test ./...` and `yaegi test` still see the same packages.
- Place `zzz_` as a prefix on the current basename (`cache_test.go` → `zzz_cache_test.go`). That is the conventional use of a `zzz_` token (sort last) and the only “add `zzz_`” shape that does not break discovery. See open questions.
- Update the one README path that names `bouncer_test.go` so the listing matches the rename. Same trail, not a new product ask.

## Open questions

- Q: Exact target spelling of `zzz_` on the filename (`cache_test_zzz_.go` vs `cache_zzz_test.go` vs `zzz_cache_test.go`)?
  Decision: assumed — prefix the current basename: `zzz_<oldname>` (`cache_test.go` → `zzz_cache_test.go`, `bouncer_logging_test.go` → `zzz_bouncer_logging_test.go`). Literal append after `.go` or after `_test` drops the file from `go test`; requirement Out of scope forbids changing CI or file lists to compensate.
  By: explore

- Q: Rename only the five dest-`main` paths, or every `*_test.go` present at implement time?
  Decision: assumed — every in-repo `*_test.go` on the apply branch at implement (after Sync), excluding `vendor/`. Dest `main` has five; extra files that land via Sync get the same prefix.
  By: explore

- Q: Update `README.md`’s local-plugin tree that still says `bouncer_test.go`?
  Decision: assumed — yes, that one path only, so the listing matches the new name. Do not rewrite the rest of the README.
  By: explore

- Q: Change `.golangci.yml` `path: (.+)_test.go`?
  Decision: assumed — no. The regex still matches `zzz_*_test.go`.
  By: explore
