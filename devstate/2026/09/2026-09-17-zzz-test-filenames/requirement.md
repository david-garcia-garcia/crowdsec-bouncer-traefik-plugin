# Requirement
IssueKey: 2026-09-17-zzz-test-filenames

## Problem
Go test files on `main` use default `*_test.go` names with no `zzz_` marker in the filename.

## Current (code)
On `origin/main` (`23ce76d`), Go test files (suffix `_test.go`):

- `bouncer_test.go`
- `bouncer_logging_test.go`
- `pkg/cache/cache_test.go`
- `pkg/configuration/configuration_test.go`
- `pkg/logger/logger_test.go`

No `*_test.go` path on this tree contains the substring `zzz_` (`not found` via tree walk at dest HEAD).

## Desired
Rename every Go test file in this repository so that `zzz_` is appended to its filename (per local ticket `ticket/source.md`). No other product behavior requested.

## Affected
All five `*_test.go` paths listed under Current. `go test` package discovery still requires valid `*_test.go` suffix unless a non-standard name is explicitly intended.

## Out of scope
Changing test logic, CI config, Makefile targets, or non-test `.go` files. Renaming on branches other than the apply branch. Interpreting the ticket as a new testing policy beyond filename renames.

## Unknowns
Exact target spelling: e.g. `cache_test_zzz_.go` vs `cache_zzz_test.go` vs `zzz_cache_test.go` — ticket says append `zzz_` to the filename, not which segment of the basename moves.

## Tensions
- Ticket wording “append `zzz_`” vs Go convention that test files must end in `_test.go` for default discovery — any pattern that breaks `_test.go` suffix would change how tests are found unless build tags or explicit file lists are added (not requested).
- Caller checkout may contain additional `*_test.go` files not on `origin/main`; prepare grounds analysis on dest `main` only.
