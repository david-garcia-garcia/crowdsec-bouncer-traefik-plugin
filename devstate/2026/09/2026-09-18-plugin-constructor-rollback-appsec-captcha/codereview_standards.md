# Code review — Standards

Pin: `origin/master` (`87d1084`). Diff excludes `devstate/` and `.cursor/`.

- [x] S1 `gofmt` / `golangci-lint run ./...` clean at `v1.63.4` settings, `enable-all` included.
  Status: pass. Argument: two misspell hits (`cancelling`) and one CRLF file were fixed before commit.
- [x] S2 New test files carry the `zzz_` prefix (`std_go_test_zzz-prefix`).
  Status: pass. `zzz_constructor_test.go`, `pkg/configuration/zzz_appsec_mode_test.go`.
- [x] S3 Named return on `New` is the only one in the tree and is justified in the doc comment, with
  `//nolint:nonamedreturns` rather than a silent suppression.
  Status: pass. Argument: the ticket requires the named-`err` defer; `nonamedreturns` is on under
  `enable-all`, so the directive is the only way to keep it.
- [x] S4 Comments state constraints, not narration (`sbs-dev-commandments`).
  Status: pass. The three added comments each name a constraint: which fields the shallow copy does
  not protect, why `bindCtx` is a child of `ctx`, and why appsec mode still needs the captcha client.
- [x] S5 Yaegi v0.16.1 constraints: no `atomic.Pointer[T]`, no new `select`-with-timer.
  Status: pass. `context.WithCancel` plus the table's existing `context.AfterFunc`. Measured with
  `yaegi test` at v0.16.1 — which also caught `t.Cleanup(srv.Close)` as a method value the
  interpreter types as `func(*httptest.Server)`; rewritten as closures like the existing tests.
- [x] S6 Commit trail has no agent trailer.
  Status: pass. `Co-authored-by: Cursor` was injected on all three commits and stripped before the
  final push.
