## Purpose

House rule for how this repository names Go test source files so they stay discoverable by `go test` while carrying a `zzz_` basename prefix.

## ADDED Requirements

### Requirement: In-repo test files use a zzz_ prefix

Every in-repo Go test source file SHALL have a basename that starts with `zzz_` and ends with `_test.go`. Files under `vendor/` are out of scope.

#### Scenario: Existing test file is renamed

- **WHEN** the tree contains an in-repo file whose basename is `cache_test.go`
- **THEN** that file SHALL be stored as `zzz_cache_test.go` in the same directory

#### Scenario: Default go test discovery still finds tests

- **WHEN** a package has only `zzz_*_test.go` sources and `go test` is run on that package
- **THEN** those files SHALL still be compiled as test files because the basename ends with `_test.go`

### Requirement: Non-test names stay unchanged

A source file that is not a Go test file SHALL keep its current basename. The `zzz_` prefix applies only to files that already ended in `_test.go`.

#### Scenario: Production source is left alone

- **WHEN** the tree contains `bouncer.go`
- **THEN** that file SHALL remain `bouncer.go`
