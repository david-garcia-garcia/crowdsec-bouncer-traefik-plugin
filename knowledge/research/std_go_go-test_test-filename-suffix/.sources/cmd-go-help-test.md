---
url: https://pkg.go.dev/cmd/go#hdr-Test_packages
title: cmd/go — Test packages
fetched: 2026-09-17
authority: official
---

'Go test' recompiles each package along with any files with names matching the file pattern "*_test.go".

These additional files can contain test functions, benchmark functions, fuzz tests and example functions.

Each listed package causes the execution of a separate test binary.

Files whose names begin with "_" (including "_test.go") or "." are ignored.

Test files that declare a package with the suffix "_test" will be compiled as a separate package, and then linked and run with the main test binary.

The 'go test' command expects to find test, benchmark, and example functions in the "*_test.go" files corresponding to the package under test.
