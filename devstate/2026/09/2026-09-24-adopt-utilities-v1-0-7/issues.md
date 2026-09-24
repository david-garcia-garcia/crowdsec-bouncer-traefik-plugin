# Issues

- [ ] note large  `knowledge/debt/2026-09-24-rename-utilities-packages-research.md`
  Why: research slug `packages` hides the object (Name for the scope).
- [x] take small  `pkg/lapi/zzz_ipcachekey_test.go` dead reader uses a closed ephemeral port
  Why: dest `127.0.0.1:1` is LISTEN on this machine, so GET returns redis:unsupported-reply not ErrUnreachable.
  Taken: `closedTestReaderAddr` binds `127.0.0.1:0` then closes it.
