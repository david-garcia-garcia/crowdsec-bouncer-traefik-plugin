## 1. Rename test files

- [ ] 1.1 After Sync, list every in-repo `*_test.go` excluding `vendor/`
- [ ] 1.2 `git mv` each listed file to `zzz_<old-basename>` in the same directory
- [ ] 1.3 Confirm no in-repo `*_test.go` remains without a `zzz_` prefix

## 2. Trail

- [ ] 2.1 Update the README local-plugin tree line from `bouncer_test.go` to `zzz_bouncer_test.go`

## 3. Verify

- [ ] 3.1 Run `go test -v -cover ./...` and record pass or fail
