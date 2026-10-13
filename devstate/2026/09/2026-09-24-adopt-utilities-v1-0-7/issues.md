# Issues

- [ ] note large  `knowledge/debt/2026-09-24-rename-utilities-packages-research.md`
  Why: research slug `packages` hides the object (Name for the scope).
- [x] take small  `pkg/lapi/zzz_ipcachekey_test.go` dead reader uses a closed ephemeral port
  Why: dest `127.0.0.1:1` is LISTEN on this machine, so GET returns redis:unsupported-reply not ErrUnreachable.
  Taken: `closedTestReaderAddr` binds `127.0.0.1:0` then closes it.
- [x] take small  Main Yaegi GOPATH overlay for utilities `traefikemulator`
  Why: Yaegi v0.16 cannot find the test-only published import from `vendor/`.
  Taken: copy vendored utilities onto `$GOPATH/src/github.com/david-garcia-garcia/traefik-middleware-utilities` before `yaegi test`.
- [x] take small  `knowledge/debt/2026-09-20-upstream-reclaim-peek.md`
  Why: v1.0.7 publishes Peek; dest skipped `go mod vendor` so the ad-hoc vendor Peek survived.
  Taken: re-enable Main `go mod vendor` and vendor git-diff; delete the debt file.
