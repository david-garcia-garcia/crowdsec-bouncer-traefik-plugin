## Context

See proposal.md Why. Dest `main` has five in-repo `*_test.go` files and no `zzz_` in those names. `make test` is `go test -v -cover ./...`. Official Go discovery treats a file as a test source only when the basename ends with `_test.go` (`knowledge/research/std_go_go-test_test-filename-suffix/`).

## Goals / Non-Goals

**Goals:**

- One mechanical rename per in-repo test file: `git mv` so history follows the file.
- Prefix the current basename with `zzz_`; do not rewrite test bodies.

**Non-Goals:**

- Changing Makefile, CI workflows, or `.golangci.yml`.
- Renaming files under `vendor/`.
- Inventing a second discovery mechanism if a name would no longer end in `_test.go`.

## Decisions

- **Prefix, not a trailing `zzz_`.** Ticket wording said “append”. A literal append (`cache_test.gozzz_` / `cache_testzzz_.go`) is not a test file. Prefix `zzz_<old>` keeps `HasSuffix(name, "_test.go")` true. Alternative `cache_zzz_test.go` also keeps discovery; rejected so the token is a leading sort-last marker and the mapping is one rule (`zzz_` + old basename).
- **Scope is the apply-branch tree after Sync, excluding `vendor/`.** Dest `main` has five files; extras that land via Sync get the same prefix.
- **README:** update only the local-plugin tree line that names `bouncer_test.go`.

## Risks / Trade-offs

- [Risk] Callers or docs that hard-code old test paths break. → Mitigation: dest `main` only hard-codes `bouncer_test.go` in README; golangci uses a suffix regex.
- [Risk] A later Sync adds a `*_test.go` that implement misses. → Mitigation: tasks.md walks the tree at apply time, not a frozen five-file list.

## Migration Plan

Rename on the apply branch. Rollback is `git revert` of the rename commit. No runtime data to migrate.

## Open Questions

None that change this design. Assumed spelling and scope live on `devstate/explore.md`.
