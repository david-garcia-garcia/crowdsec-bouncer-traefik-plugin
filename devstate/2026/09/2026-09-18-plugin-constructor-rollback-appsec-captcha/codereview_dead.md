# Code review — Dead

- [x] D1 No unreachable defensive plumbing was added. The ticket explicitly refused #33's error
  returns for `ip.NewChecker` and `GetTemplate`.
  Status: pass. Argument: `ValidateParams` rejects those inputs first
  (`configuration.go:319`, `:322`, `:362-366`) and `ip.Checker.ContainsIP` has a nil guard that
  trusts nothing, so the swallowed error already fails closed. Not ported.
- [x] D2 `releaseHolders` is reachable on every error path after it is created, and unreachable
  before it — the three `return nil, err` above the `defer` are pre-`Open`, so nothing is held yet.
  Status: pass.
- [x] D3 `handler` named return is assigned exactly once, immediately before the final `return`.
  Status: accepted. Argument: it exists only because Go requires all results to be named once `err`
  is. Written as an explicit assignment plus `return handler, err` rather than `return bouncer.New(…)`
  so the interpreter has no tail-call form to get wrong.
- [x] D4 `warnUnenforcedAppsecMode` has exactly one caller and both branches are covered by tests.
  Status: pass.
